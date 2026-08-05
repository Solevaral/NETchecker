//! Оркестратор диагностики.
//!
//! Проверки идут снизу вверх по модели OSI, и порядок здесь не косметический:
//! вывод верхнего уровня имеет смысл только в свете нижнего. Если роутер
//! недоступен, «сайт не открывается» — не диагноз, а следствие.
//!
//! Единственное исключение из порядка — поиск средств обхода. Он идёт вторым,
//! сразу после осмотра интерфейсов: если трафик уже уходит в туннель, об этом
//! нужно сказать до того, как человек начнёт верить остальным цифрам.
//!
//! Всё выполняется в отдельном потоке и рапортует в UI через [`Reporter`].

pub mod bypass;
pub mod icmp;
pub mod l1_l2;
pub mod probe;
pub mod trace;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use crate::bus::{EngineEvent, Reporter};
use crate::model::{CheckResult, Diagnosis, Layer, NodeId, Status};
use crate::privileged::Capabilities;

use icmp::{Pinger, ReplyKind};
use probe::{ms, tcp_connect, TcpOutcome};

/// Опорные точки интернета. Разные операторы и разные страны — если недоступны
/// сразу все, дело почти наверняка не в них.
const ANCHORS: [(&str, Ipv4Addr); 3] = [
    ("Cloudflare", Ipv4Addr::new(1, 1, 1, 1)),
    ("Google", Ipv4Addr::new(8, 8, 8, 8)),
    ("Яндекс", Ipv4Addr::new(77, 88, 8, 8)),
];

/// Домены для проверки прикладного уровня.
const SITES: [&str; 2] = ["ya.ru", "example.com"];

const TIMEOUT: Duration = Duration::from_secs(4);
const PING_TIMEOUT: Duration = Duration::from_millis(1500);

/// Сколько эхо-запросов шлём на один адрес: по четырём пробам уже видно
/// и потери, и разброс задержки.
const PING_COUNT: usize = 4;

/// Всего шагов в конвейере — должно совпадать с числом вызовов `progress`.
const STEPS: usize = 6;

/// Запускает диагностику в фоне. Вызывающий продолжает рисовать окно.
pub fn spawn(caps: Capabilities, rep: Reporter) {
    thread::spawn(move || run(caps, &rep));
}

fn run(caps: Capabilities, rep: &Reporter) {
    rep.send(EngineEvent::Started { total: STEPS });

    rep.progress(0, "Проверяю сетевой адаптер и роутер…");
    let link = l1_l2::run(rep);

    rep.progress(1, "Ищу VPN, прокси и средства обхода…");
    let bypass = check_bypass(rep, &link);

    let pinger = Pinger::new(caps);
    if pinger.is_none() {
        rep.check(
            CheckResult::new("l3.icmp", Layer::L3Network, NodeId::Pc, "Доступность ICMP").finish(
                Status::Skipped,
                "Система не разрешила программе отправлять эхо-запросы, поэтому точные замеры \
                 задержек и трассировка недоступны. Остальные проверки пойдут через TCP.",
                caps.icmp.explanation(),
            ),
        );
    }

    rep.progress(2, "Проверяю отклик роутера…");
    let router_alive = check_router(rep, pinger.as_ref(), link.gateway);

    rep.progress(3, "Проверяю выход в интернет…");
    let reachable_anchor = check_anchors(rep, pinger.as_ref(), caps);

    rep.progress(4, "Строю маршрут до интернета…");
    let route = check_route(rep, pinger.as_ref(), &link, reachable_anchor);

    rep.progress(5, "Проверяю имена сайтов и соединение с ними…");
    let dns_ok = check_dns_and_sites(rep, &link);

    rep.progress(STEPS, "Готово");
    rep.send(EngineEvent::Finished(Box::new(verdict(Observations {
        link: &link,
        bypass: &bypass,
        router_alive,
        anchors_ok: reachable_anchor.is_some(),
        route: &route,
        dns_ok,
    }))));
}

/// Поиск VPN, прокси и средств обхода блокировок.
fn check_bypass(rep: &Reporter, link: &l1_l2::LinkInfo) -> bypass::Report {
    let report = bypass::detect(&link.interfaces, link.default_is_tunnel);

    let check = CheckResult::new(
        "l2.bypass",
        Layer::L2Link,
        NodeId::Pc,
        "VPN, прокси и обходы блокировок",
    );

    let check = if report.is_empty() {
        check.finish(
            Status::Ok,
            "Ни VPN, ни прокси, ни средств обхода блокировок не найдено — проверяется \
             ваше обычное подключение.",
            "Не найдено ни туннельных интерфейсов, ни известных процессов, \
             ни слушающих локальных прокси-портов.",
        )
    } else if report.traffic_is_tunneled() {
        check.finish(
            Status::Warn,
            format!(
                "{} Весь трафик идёт через туннель, поэтому проверки ниже описывают канал \
                 туннеля, а не то, что даёт ваш провайдер. Чтобы проверить провайдера, \
                 отключите VPN и повторите.",
                report.summary()
            ),
            "Маршрут по умолчанию уходит в туннельный интерфейс.",
        )
    } else {
        check.finish(
            Status::Warn,
            format!(
                "{} Средства запущены, но весь трафик через них не идёт: часть приложений \
                 может ходить в обход, часть — напрямую.",
                report.summary()
            ),
            "Найдены средства обхода, но маршрут по умолчанию идёт мимо туннеля.",
        )
    };

    let check = report.findings.iter().fold(check, |c, f| {
        c.with_evidence(format!(
            "{} · {} — {}",
            f.kind.title(),
            f.name,
            f.evidence
        ))
    });
    rep.check(check);

    report
}

/// Отвечает ли сам роутер.
///
/// С ICMP это прямой ответ на вопрос. Без него судим по TCP: и открытый порт,
/// и явный отказ одинаково доказывают, что устройство на связи.
fn check_router(rep: &Reporter, pinger: Option<&Pinger>, gateway: Option<IpAddr>) -> Option<bool> {
    let Some(gw) = gateway else {
        rep.check(
            CheckResult::new("l3.router", Layer::L3Network, NodeId::Router, "Отклик роутера")
                .finish(
                    Status::Skipped,
                    "Проверка пропущена: адрес роутера неизвестен.",
                    "Нет шлюза по умолчанию.",
                ),
        );
        return None;
    };

    let check = CheckResult::new("l3.router", Layer::L3Network, NodeId::Router, "Отклик роутера");

    if let (Some(pinger), IpAddr::V4(gw4)) = (pinger, gw) {
        let stats = ping_stats(pinger, gw4);
        let check = if stats.received > 0 {
            check.finish(
                Status::Ok,
                format!(
                    "Роутер {gw} отвечает, время отклика — {}. Связь с ним есть.",
                    stats.best_text()
                ),
                format!("ICMP: {}.", stats.describe()),
            )
        } else {
            check.finish(
                Status::Warn,
                format!(
                    "Роутер {gw} не отвечает на запросы. Часть роутеров молчит намеренно, \
                     поэтому смотрите проверки ниже."
                ),
                format!("ICMP: {}.", stats.describe()),
            )
        };
        rep.check(check.with_evidence(format!("{gw}: {}", stats.describe())));
        return Some(stats.received > 0);
    }

    let mut evidence = Vec::new();
    let mut alive = false;
    for port in [80u16, 443, 53] {
        let outcome = tcp_connect(SocketAddr::new(gw, port), Duration::from_millis(800));
        evidence.push(format!("TCP {gw}:{port} — {}", outcome.describe()));
        if matches!(outcome, TcpOutcome::Open { .. } | TcpOutcome::Refused { .. }) {
            alive = true;
        }
    }

    let check = if alive {
        check.finish(
            Status::Ok,
            format!("Роутер {gw} отвечает — до него связь есть."),
            "Роутер ответил на TCP-пробу (соединением или явным отказом).",
        )
    } else {
        check.finish(
            Status::Warn,
            format!("Роутер {gw} не ответил на пробу. Часть роутеров молчит намеренно."),
            "Ни один из портов 80/443/53 не дал ответа, ICMP недоступен.",
        )
    };
    rep.check(evidence.into_iter().fold(check, |c, e| c.with_evidence(e)));

    Some(alive)
}

/// Доступны ли опорные узлы интернета. Возвращает первый достижимый — он же
/// станет целью трассировки.
fn check_anchors(
    rep: &Reporter,
    pinger: Option<&Pinger>,
    caps: Capabilities,
) -> Option<Ipv4Addr> {
    let mut evidence = Vec::new();
    let mut reachable: Vec<&str> = Vec::new();
    let mut first: Option<Ipv4Addr> = None;

    for (name, ip) in ANCHORS {
        let (ok, line) = match pinger {
            Some(p) => {
                let stats = ping_stats(p, ip);
                (stats.received > 0, format!("{name} {ip} — {}", stats.describe()))
            }
            None => {
                let outcome = tcp_connect(SocketAddr::new(IpAddr::V4(ip), 443), TIMEOUT);
                (
                    outcome.is_open(),
                    format!("{name} {ip}:443 — {}", outcome.describe()),
                )
            }
        };
        evidence.push(line);
        if ok {
            reachable.push(name);
            first.get_or_insert(ip);
        }
    }

    let check = CheckResult::new(
        "l4.anchors",
        Layer::L4Transport,
        NodeId::Internet,
        "Связь с интернетом",
    );
    let check = if let Some(anchor) = first {
        rep.node(
            NodeId::Internet,
            format!("отвечает {}", reachable.first().copied().unwrap_or("")),
            Some(anchor.to_string()),
        );
        check.finish(
            Status::Ok,
            format!("Интернет доступен: отвечают {}.", reachable.join(", ")),
            format!(
                "Ответили {} из {} опорных узлов.",
                reachable.len(),
                ANCHORS.len()
            ),
        )
    } else {
        rep.node(NodeId::Internet, "недоступен", None);
        check.finish(
            Status::Fail,
            "Ни один сервер в интернете не отвечает. Дальше локальной сети трафик не уходит.",
            "Все опорные узлы промолчали.",
        )
    };

    let check = check.with_evidence(format!(
        "Режим замеров: {} — {}",
        caps.icmp.title(),
        caps.icmp.explanation()
    ));
    rep.check(evidence.into_iter().fold(check, |c, e| c.with_evidence(e)));

    first
}

/// Трассировка: где проходит путь и где он обрывается.
///
/// Именно она наполняет узлы «Провайдер» и «Фильтрация» — до неё они пустые,
/// потому что до трассировки о них просто нечего сказать.
fn check_route(
    rep: &Reporter,
    pinger: Option<&Pinger>,
    link: &l1_l2::LinkInfo,
    anchor: Option<Ipv4Addr>,
) -> trace::Trace {
    let Some(pinger) = pinger else {
        rep.check(
            CheckResult::new("l3.trace", Layer::L3Network, NodeId::Provider, "Маршрут в интернет")
                .finish(
                    Status::Skipped,
                    "Трассировка недоступна: система не разрешила отправку эхо-запросов.",
                    "Нет ICMP-транспорта — построить маршрут по TTL нечем.",
                ),
        );
        return trace::Trace::default();
    };

    // Если не отозвался ни один якорь, всё равно трассируем: как раз важно
    // увидеть, до какого места путь ещё жив.
    let target = anchor.unwrap_or(ANCHORS[0].1);

    let result = trace::run(pinger, target, &link.local_v4, |hop| {
        rep.progress(4, format!("Маршрут: узел {} из {}", hop.ttl, trace::MAX_HOPS));
    });

    // ---- узел «Провайдер» --------------------------------------------------
    let provider = CheckResult::new(
        "l3.trace",
        Layer::L3Network,
        NodeId::Provider,
        "Маршрут в интернет",
    );
    let provider = match &result.first_external {
        Some(hop) => {
            let addr = hop.address.map(|a| a.to_string()).unwrap_or_default();
            rep.node(
                NodeId::Provider,
                format!("{}-й узел пути", hop.ttl),
                Some(addr.clone()),
            );
            provider.finish(
                Status::Ok,
                format!(
                    "Трафик выходит за пределы домашней сети: первый узел провайдера — {addr}, \
                     он {}-й на пути.",
                    hop.ttl
                ),
                format!(
                    "Первый внешний хоп {addr} на TTL {}, участок: {}. Всего узлов: {}.",
                    hop.ttl,
                    hop.segment.map(|s| s.title()).unwrap_or("не определён"),
                    result.hops.len()
                ),
            )
        }
        None => {
            rep.node(NodeId::Provider, "путь не выходит наружу", None);
            provider.finish(
                Status::Fail,
                "Трафик не выходит за пределы частных сетей — до провайдера он не доходит. \
                 Все узлы на пути имеют «домашние» адреса, снаружи их не существует.",
                "Ни одного хопа с публичным адресом или адресом CGNAT.",
            )
        }
    };
    let provider = result
        .hops
        .iter()
        .fold(provider, |c, h| c.with_evidence(h.describe()));
    rep.check(provider);

    // ---- узел «Фильтрация» -------------------------------------------------
    let filter = CheckResult::new(
        "l3.filter",
        Layer::L3Network,
        NodeId::Dpi,
        "Фильтрация на пути",
    );
    let prohibited = result.hops.iter().find(|h| h.prohibited);

    let filter = if let Some(hop) = prohibited {
        let addr = hop.address.map(|a| a.to_string()).unwrap_or_default();
        rep.node(NodeId::Dpi, "запрет на узле", Some(addr.clone()));
        filter.finish(
            Status::Fail,
            format!(
                "Узел {addr} на пути прямо запрещает пропускать трафик. Это оборудование \
                 фильтрации, а не поломка."
            ),
            format!("Хоп {} ({addr}) вернул ICMP «прохождение запрещено административно».", hop.ttl),
        )
    } else if result.reached {
        rep.node(NodeId::Dpi, "признаков не найдено", None);
        filter.finish(
            Status::Ok,
            "На пути до интернета оборудование не блокирует трафик — маршрут прошёл целиком.",
            "Трассировка дошла до цели, ICMP-запретов по пути нет. Проверка блокировок \
             по имени сайта и по SNI появится на следующем этапе.",
        )
    } else if let Some(hop) = result.break_after() {
        let addr = hop.address.map(|a| a.to_string()).unwrap_or_default();
        let segment = hop.segment.map(|s| s.title()).unwrap_or("неизвестный участок");
        rep.node(NodeId::Dpi, "путь обрывается", Some(addr.clone()));
        filter.finish(
            Status::Warn,
            format!(
                "Путь обрывается после узла {addr} ({segment}). Дальше пакеты уходят \
                 без ответа — так выглядит и перегруженный узел, и фильтрация."
            ),
            format!(
                "Последний ответивший хоп — {} ({addr}). Молчащих узлов подряд: {}. \
                 Часть узлов не отвечает на ICMP намеренно, поэтому один этот признак \
                 ещё не доказывает блокировку.",
                hop.ttl,
                result.silent_tail()
            ),
        )
    } else {
        rep.node(NodeId::Dpi, "нет данных", None);
        filter.finish(
            Status::Skipped,
            "Определить наличие фильтрации не удалось: маршрут не построился.",
            "Трассировка не дала ни одного ответившего узла.",
        )
    };
    rep.check(filter);

    result
}

/// Разрешаются ли имена и открываются ли по ним соединения.
fn check_dns_and_sites(rep: &Reporter, link: &l1_l2::LinkInfo) -> bool {
    let servers = if link.dns_servers.is_empty() {
        "система не сообщила список".to_string()
    } else {
        link.dns_servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut resolved_any = false;
    let mut evidence = vec![format!("DNS-серверы системы: {servers}")];

    for site in SITES {
        match (site, 443u16).to_socket_addrs() {
            Ok(addrs) => {
                let list: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
                if list.is_empty() {
                    evidence.push(format!("{site} — имя не разрешилось ни в один адрес"));
                } else {
                    resolved_any = true;
                    evidence.push(format!("{site} → {}", list.join(", ")));
                }
            }
            Err(e) => evidence.push(format!("{site} — ошибка разрешения имени: {e}")),
        }
    }

    let dns = CheckResult::new("l7.dns", Layer::L7Application, NodeId::Internet, "Имена сайтов");
    let dns = if resolved_any {
        dns.finish(
            Status::Ok,
            "Имена сайтов превращаются в адреса — DNS работает.",
            "Системный резолвер вернул адреса. Сравнение с DoH и проверка подмены — следующий этап.",
        )
    } else {
        dns.finish(
            Status::Fail,
            "Компьютер не может узнать адреса сайтов по их именам. Обычно это отказ DNS.",
            "Системный резолвер не вернул ни одной записи.",
        )
    };
    rep.check(evidence.into_iter().fold(dns, |c, e| c.with_evidence(e)));

    // Соединение с конкретным сайтом — отдельная проверка: DNS может работать,
    // а соединение при этом обрываться.
    let site = SITES[0];
    let conn = CheckResult::new(
        "l7.site",
        Layer::L7Application,
        NodeId::Target,
        format!("Соединение с {site}"),
    );
    let conn = match (site, 443u16).to_socket_addrs().map(|mut a| a.next()) {
        Ok(Some(addr)) => {
            rep.node(NodeId::Target, site, Some(addr.ip().to_string()));
            let outcome = tcp_connect(addr, TIMEOUT);
            match &outcome {
                TcpOutcome::Open { rtt } => conn.finish(
                    Status::Ok,
                    format!("Сайт {site} открывается, ответ за {} мс.", ms(*rtt)),
                    format!("TCP {addr} установлено за {} мс.", ms(*rtt)),
                ),
                _ => conn.finish(
                    Status::Fail,
                    format!("До сайта {site} не удаётся достучаться."),
                    format!("TCP {addr}: {}", outcome.describe()),
                ),
            }
        }
        _ => conn.finish(
            Status::Skipped,
            "Проверка пропущена: адрес сайта не удалось узнать.",
            "Имя не разрешилось, соединение проверять не по чему.",
        ),
    };
    rep.check(conn);

    resolved_any
}

/// Результат серии эхо-запросов к одному адресу.
struct PingStats {
    sent: usize,
    received: usize,
    best: Option<Duration>,
    worst: Option<Duration>,
    /// Самая содержательная из полученных реакций.
    kind: ReplyKind,
    /// Пояснение от транспорта, если он его дал: код ошибки, тип ICMP.
    detail: Option<String>,
}

impl PingStats {
    fn best_text(&self) -> String {
        self.best
            .map(trace::format_rtt)
            .unwrap_or_else(|| "—".to_string())
    }

    fn describe(&self) -> String {
        let note = self
            .detail
            .as_ref()
            .map(|d| format!(" ({d})"))
            .unwrap_or_default();
        if self.received == 0 {
            return format!(
                "{} из {} запросов без ответа, {}{note}",
                self.sent,
                self.sent,
                self.kind.describe()
            );
        }
        let jitter = match (self.best, self.worst) {
            (Some(b), Some(w)) if w > b => format!(", разброс до {} мс", (w - b).as_millis()),
            _ => String::new(),
        };
        format!(
            "ответов {}/{}, лучшее время {}{jitter}, {}{note}",
            self.received,
            self.sent,
            self.best_text(),
            self.kind.describe()
        )
    }
}

fn ping_stats(pinger: &Pinger, target: Ipv4Addr) -> PingStats {
    let mut stats = PingStats {
        sent: PING_COUNT,
        received: 0,
        best: None,
        worst: None,
        kind: ReplyKind::Timeout,
        detail: None,
    };

    for _ in 0..PING_COUNT {
        let reply = pinger.ping(target, 64, PING_TIMEOUT);
        if stats.detail.is_none() {
            stats.detail = reply.detail.clone();
        }
        if reply.kind == ReplyKind::Echo {
            stats.received += 1;
            stats.kind = ReplyKind::Echo;
            if let Some(rtt) = reply.rtt {
                stats.best = Some(stats.best.map_or(rtt, |b: Duration| b.min(rtt)));
                stats.worst = Some(stats.worst.map_or(rtt, |w: Duration| w.max(rtt)));
            }
        } else if stats.kind == ReplyKind::Timeout && reply.kind.got_response() {
            // Запоминаем содержательный отказ: он объясняет больше, чем тишина.
            stats.kind = reply.kind;
        }
    }

    stats
}

/// Всё, что удалось выяснить, — вход для правил вывода.
struct Observations<'a> {
    link: &'a l1_l2::LinkInfo,
    bypass: &'a bypass::Report,
    router_alive: Option<bool>,
    anchors_ok: bool,
    route: &'a trace::Trace,
    dns_ok: bool,
}

/// Сведение наблюдений в один понятный вывод.
fn verdict(o: Observations<'_>) -> Diagnosis {
    // Оговорка про туннель добавляется к любому исходу: без неё верные цифры
    // приведут к неверному выводу о провайдере.
    let tunnel_note = |mut actions: Vec<String>| {
        if o.bypass.traffic_is_tunneled() {
            actions.insert(
                0,
                "Трафик идёт через VPN. Чтобы проверить именно провайдера, отключите его \
                 и повторите проверку."
                    .to_string(),
            );
        }
        actions
    };

    if o.link.interface.is_none() {
        return Diagnosis {
            headline: "Нет сетевого подключения".into(),
            simple: "Компьютер не видит ни одного работающего подключения к сети.".into(),
            expert: "Нет ни одного не-loopback интерфейса в состоянии UP.".into(),
            actions: vec![
                "Проверьте, воткнут ли сетевой кабель.".into(),
                "Проверьте, включён ли Wi-Fi.".into(),
                "Убедитесь, что сетевой адаптер не отключён в системе.".into(),
            ],
            break_edge: Some((NodeId::Pc, NodeId::Router)),
            status: Status::Fail,
        };
    }

    if o.link.gateway.is_none() {
        return Diagnosis {
            headline: "Роутер недоступен".into(),
            simple: "Подключение есть, но компьютер не знает, через что выходить в интернет. \
                     Чаще всего это значит, что роутер завис или кабель до него не работает."
                .into(),
            expert: "Отсутствует маршрут по умолчанию.".into(),
            actions: vec![
                "Перезагрузите роутер, подождите минуту.".into(),
                "Проверьте кабель между компьютером и роутером.".into(),
            ],
            break_edge: Some((NodeId::Pc, NodeId::Router)),
            status: Status::Fail,
        };
    }

    if !o.anchors_ok {
        // Трассировка позволяет сказать не просто «интернета нет»,
        // а до какого места он ещё есть.
        let (edge, simple, expert) = match o.route.first_external.as_ref() {
            Some(hop) => {
                let addr = hop.address.map(|a| a.to_string()).unwrap_or_default();
                (
                    (NodeId::Provider, NodeId::Internet),
                    format!(
                        "Роутер работает, трафик доходит до сети провайдера (узел {addr}), \
                         но дальше в интернет не проходит. Похоже на неполадку у провайдера."
                    ),
                    format!(
                        "Путь жив до {addr}, затем {} молчащих узлов подряд, опорные узлы \
                         не отвечают.",
                        o.route.silent_tail()
                    ),
                )
            }
            None if o.router_alive == Some(true) => (
                (NodeId::Router, NodeId::Provider),
                "Роутер отвечает, но дальше него трафик не уходит. Скорее всего, интернет \
                 не даёт провайдер."
                    .to_string(),
                "Шлюз отвечает, ни одного внешнего хопа не построено.".to_string(),
            ),
            None => (
                (NodeId::Router, NodeId::Provider),
                "Локальная сеть есть, но выхода в интернет нет.".to_string(),
                "Ни одного внешнего хопа, опорные узлы не отвечают.".to_string(),
            ),
        };

        return Diagnosis {
            headline: "Интернета нет за роутером".into(),
            simple,
            expert,
            actions: tunnel_note(vec![
                "Перезагрузите роутер.".into(),
                "Проверьте баланс и статус услуги у провайдера.".into(),
                "Если интернет мобильный — проверьте, не отключён ли он в вашем районе.".into(),
            ]),
            break_edge: Some(edge),
            status: Status::Fail,
        };
    }

    if !o.dns_ok {
        return Diagnosis {
            headline: "Интернет есть, но имена сайтов не работают".into(),
            simple: "Соединения с интернетом проходят, а вот превратить имя сайта в адрес \
                     не получается. Обычно виноват DNS-сервер."
                .into(),
            expert: "Опорные узлы доступны по IP, системный резолвер записей не вернул.".into(),
            actions: tunnel_note(vec![
                "Попробуйте прописать DNS 1.1.1.1 или 77.88.8.8.".into(),
                "Перезагрузите роутер — часто он же и раздаёт DNS.".into(),
            ]),
            break_edge: Some((NodeId::Internet, NodeId::Target)),
            status: Status::Fail,
        };
    }

    if let Some(hop) = o.route.hops.iter().find(|h| h.prohibited) {
        let addr = hop.address.map(|a| a.to_string()).unwrap_or_default();
        return Diagnosis {
            headline: "На пути стоит фильтрация".into(),
            simple: format!(
                "Интернет в целом работает, но узел {addr} на пути прямо запрещает пропускать \
                 часть трафика."
            ),
            expert: format!("Хоп {} ({addr}) вернул ICMP «административно запрещено».", hop.ttl),
            actions: tunnel_note(Vec::new()),
            break_edge: None,
            status: Status::Warn,
        };
    }

    let mut actions = Vec::new();
    if !o.bypass.is_empty() {
        actions.push(format!(
            "{} Учитывайте это при чтении результатов.",
            o.bypass.summary()
        ));
    }

    Diagnosis {
        headline: "Интернет работает".into(),
        simple: "Подключение, роутер, выход в интернет и имена сайтов — всё отвечает.".into(),
        expert: format!(
            "L1–L4 и разрешение имён в норме, маршрут построен на {} узлов. Проверки \
             на блокировки, подмену DNS и замедление появятся на следующих этапах.",
            o.route.hops.len()
        ),
        actions: tunnel_note(actions),
        break_edge: None,
        status: if o.bypass.is_empty() {
            Status::Ok
        } else {
            Status::Warn
        },
    }
}
