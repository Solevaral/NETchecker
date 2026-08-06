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
pub mod censorship;
pub mod dns;
pub mod icmp;
pub mod l1_l2;
pub mod probe;
pub mod tls;
pub mod trace;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use crate::bus::{EngineEvent, Reporter};
use crate::model::{CheckResult, Diagnosis, Layer, NodeId, Status};
use crate::privileged::Capabilities;
use crate::targets::{Kind, Target, TargetList};

use icmp::{Pinger, ReplyKind};
use probe::{ms, tcp_connect, TcpOutcome};

/// Опорные точки интернета. Разные операторы и разные страны — если недоступны
/// сразу все, дело почти наверняка не в них.
const ANCHORS: [(&str, Ipv4Addr); 3] = [
    ("Cloudflare", Ipv4Addr::new(1, 1, 1, 1)),
    ("Google", Ipv4Addr::new(8, 8, 8, 8)),
    ("Яндекс", Ipv4Addr::new(77, 88, 8, 8)),
];

/// Имя, которое подставляется вместо настоящего, чтобы отделить «сервер не
/// отвечает» от «не пускают именно это имя».
const NEUTRAL_SNI: &str = "example.org";

/// DoH-серверы задаются числовыми адресами: если DNS сломан или подменён,
/// разрешать имя самого DoH-сервера было бы замкнутым кругом. Сертификаты
/// обоих серверов выписаны в том числе на их адреса.
const DOH_ENDPOINTS: [&str; 2] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];

/// Адрес из диапазона, зарезервированного для документации: там заведомо нет
/// и не может быть DNS-сервера. Ответ от него означает, что запросы к порту 53
/// перехватывает провайдер.
const NOWHERE_RESOLVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

const TIMEOUT: Duration = Duration::from_secs(4);
const PING_TIMEOUT: Duration = Duration::from_millis(1500);

/// Тайм-аут проб на блокировки. Короче общего намеренно: заблокированная цель
/// как раз и молчит, а таких целей в списке может быть много — общий тайм-аут
/// превратил бы проверку в многоминутное ожидание.
const PROBE_TIMEOUT: Duration = Duration::from_millis(2500);

/// Сколько целей проверяется одновременно.
///
/// Пробы почти всё время просто ждут ответа, поэтому параллельность упирается
/// не в процессор, а в желание не устраивать провайдеру всплеск соединений.
const PARALLEL_TARGETS: usize = 6;

/// Сколько эхо-запросов шлём на один адрес: по четырём пробам уже видно
/// и потери, и разброс задержки.
const PING_COUNT: usize = 4;

/// Всего шагов в конвейере — должно совпадать с числом вызовов `progress`.
const STEPS: usize = 7;

/// Запускает диагностику в фоне. Вызывающий продолжает рисовать окно.
pub fn spawn(caps: Capabilities, targets: TargetList, rep: Reporter) {
    thread::spawn(move || run(caps, &targets, &rep));
}

fn run(caps: Capabilities, targets: &TargetList, rep: &Reporter) {
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
    let dns_ok = check_dns_and_sites(rep, &link, targets);

    rep.progress(6, "Проверяю блокировки…");
    let transit = if dns_ok && reachable_anchor.is_some() {
        check_censorship(rep, &link, &bypass, targets)
    } else {
        // Без работающего интернета пробы на блокировки ничего не покажут:
        // всё будет обрываться по совсем другой причине.
        rep.check(
            CheckResult::new("l7.filter", Layer::L7Application, NodeId::Dpi, "Блокировки")
                .finish(
                    Status::Skipped,
                    "Проверка блокировок пропущена: сначала нужно, чтобы работал сам интернет.",
                    "Нет доступа к опорным узлам или к DNS — пробы неотличимы от общего обрыва.",
                ),
        );
        censorship::Transit::default()
    };

    rep.progress(STEPS, "Готово");
    rep.send(EngineEvent::Finished(Box::new(verdict(Observations {
        link: &link,
        bypass: &bypass,
        router_alive,
        anchors_ok: reachable_anchor.is_some(),
        route: &route,
        dns_ok,
        transit: &transit,
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
            "Трассировка дошла до цели, ICMP-запретов по пути нет. Фильтрация по имени \
             сайта проверяется отдельно — она на трассировке не видна.",
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
///
/// Имена берутся из пользовательского списка: проверять надо то, что не
/// открывается у человека, а не то, что было записано в коде.
fn check_dns_and_sites(rep: &Reporter, link: &l1_l2::LinkInfo, targets: &TargetList) -> bool {
    let servers = if link.dns_servers.is_empty() {
        "система не сообщила список".to_string()
    } else {
        link.dns_servers
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    // Для проверки самого DNS хватает первых нескольких имён: если резолвер
    // сломан, это видно сразу, а гонять весь список второй раз незачем —
    // подробности по каждой цели даёт проверка блокировок.
    let domains: Vec<&str> = targets
        .items()
        .iter()
        .filter(|t| t.is_domain())
        .map(|t| t.value.as_str())
        .take(3)
        .collect();

    if domains.is_empty() {
        rep.check(
            CheckResult::new("l7.dns", Layer::L7Application, NodeId::Internet, "Имена сайтов")
                .finish(
                    Status::Skipped,
                    "В списке целей нет ни одного имени сайта — проверять разрешение имён \
                     не на чем. Добавьте домены на вкладке «Цели».",
                    "Список целей состоит только из адресов.",
                )
                .with_evidence(format!("DNS-серверы системы: {servers}")),
        );
        return false;
    }

    let mut resolved_any = false;
    let mut evidence = vec![format!("DNS-серверы системы: {servers}")];

    for site in &domains {
        match (*site, 443u16).to_socket_addrs() {
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
            "Системный резолвер вернул адреса. Сравнение с эталонным ответом по HTTPS \
             идёт отдельно, по каждому проверяемому сайту.",
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
    let site = domains[0];
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

/// Проверка блокировок: сравнение DNS и пробы по имени сайта.
fn check_censorship(
    rep: &Reporter,
    link: &l1_l2::LinkInfo,
    bypass: &bypass::Report,
    targets: &TargetList,
) -> censorship::Transit {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(6)))
        .build()
        .into();

    check_dns_interception(rep, link);

    let mut probes = Vec::new();
    let mut findings = Vec::new();
    let items = targets.items();
    let total = items.len();
    let mut done = 0;

    // Цели проверяются пачками параллельно. Последовательно список из двух
    // десятков сайтов занимал бы минуты: каждая недоступная цель — это
    // несколько тайм-аутов подряд, и человек всё это время смотрит в пустоту.
    for chunk in items.chunks(PARALLEL_TARGETS) {
        rep.progress(
            6,
            format!(
                "Проверяю блокировки: {} ({}/{total})",
                chunk.iter().map(|t| t.value.as_str()).collect::<Vec<_>>().join(", "),
                done + chunk.len()
            ),
        );

        let batch: Vec<censorship::Probe> = thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|target| scope.spawn(|| probe_target(&agent, link, target)))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("проба не должна паниковать"))
                .collect()
        });
        done += chunk.len();

        for probe in batch {
            let finding = censorship::judge(&probe);

            let status = match finding.verdict {
                censorship::Verdict::Reachable => Status::Ok,
                censorship::Verdict::Unclear => Status::Skipped,
                censorship::Verdict::SiteDown => Status::Warn,
                _ => Status::Fail,
            };

            let check = CheckResult::new(
                format!("l7.target.{}", finding.domain),
                Layer::L7Application,
                NodeId::Target,
                format!("{} — {}", finding.domain, finding.verdict.headline()),
            )
            .finish(status, finding.simple.clone(), finding.expert.clone());
            rep.check(
                finding
                    .evidence
                    .iter()
                    .fold(check, |c, e| c.with_evidence(e.clone())),
            );

            probes.push(probe);
            findings.push(finding);
        }
    }

    let transit = censorship::transit_signals(&probes, &findings);

    let check = CheckResult::new(
        "l7.filter",
        Layer::L7Application,
        NodeId::Dpi,
        "Фильтрация по имени сайта",
    );
    let check = if transit.is_confident() {
        rep.node(NodeId::Dpi, "фильтрует по имени сайта", None);
        check.finish(Status::Fail, transit.simple(), transit.expert())
    } else if transit.has_signals() {
        rep.node(NodeId::Dpi, "есть отдельные признаки", None);
        check.finish(Status::Warn, transit.simple(), transit.expert())
    } else if let Some(tool) = bypass.dpi_bypass_name() {
        // Обход как раз и занимается тем, что мешает фильтру увидеть имя
        // сайта. Пока он работает, отсутствие блокировок ничего не доказывает,
        // и говорить «блокировок нет» было бы прямой неправдой.
        rep.node(NodeId::Dpi, "скрыто работающим обходом", None);
        check.finish(
            Status::Warn,
            format!(
                "Ни один сайт не обрывается по имени, но у вас работает {tool} — средство, \
                 которое как раз и прячет имя сайта от фильтра. Пока оно включено, сказать, \
                 есть блокировки или нет, невозможно. Чтобы проверить, отключите его \
                 и повторите."
            ),
            format!(
                "{} Результат снят при активном обходе DPI, поэтому отрицательный вывод \
                 недостоверен.",
                transit.expert()
            ),
        )
    } else {
        check.finish(
            Status::Ok,
            "Ни один из проверенных сайтов не обрывается из-за своего имени — фильтрации \
             по имени не видно.",
            transit.expert(),
        )
    };
    rep.check(check);

    transit
}

/// Собирает всё, что нужно знать об одной цели.
fn probe_target(
    agent: &ureq::Agent,
    link: &l1_l2::LinkInfo,
    target: &Target,
) -> censorship::Probe {
    let domain = target.value.as_str();
    let mut probe = censorship::Probe::new(domain);

    match target.kind {
        // У голого адреса нет имени, спрашивать DNS не о чем. Проверка имени
        // для него тоже бессмысленна — остаётся сама доступность.
        Kind::Address(addr) => probe.address = Some(addr),
        Kind::Domain => {
            // Эталон: ответ, который провайдер не может подменить.
            for endpoint in DOH_ENDPOINTS {
                if let Ok(answer) = dns::query_doh(agent, endpoint, domain) {
                    probe.doh = Some(answer);
                    break;
                }
            }

            // Ответ того сервера, который назначила система.
            if let Some(server) = link.dns_servers.first() {
                probe.system_dns = dns::query_udp(*server, domain, Duration::from_secs(3)).ok();
            }

            // Пробы идут на адрес из DoH: он заведомо настоящий.
            probe.address = probe
                .doh
                .as_ref()
                .and_then(|a| a.addresses.first().copied())
                .or_else(|| {
                    probe
                        .system_dns
                        .as_ref()
                        .and_then(|a| a.addresses.first().copied())
                });
        }
    }

    let Some(address) = probe.address else {
        return probe;
    };

    // Опорное время: быстрее этого сам сервер ответить не может.
    let endpoint = SocketAddr::new(IpAddr::V4(address), 443);
    let mut connect = tcp_connect(endpoint, PROBE_TIMEOUT);
    if matches!(connect, TcpOutcome::Timeout) {
        // Короткий тайм-аут выбран ради скорости, но объявлять по нему
        // блокировку нельзя: так же выглядит и разовая потеря пакета.
        // Переспрашиваем с полным запасом времени — и только если снова
        // тишина, считаем, что до адреса действительно не достучаться.
        connect = tcp_connect(endpoint, TIMEOUT);
    }
    match connect {
        TcpOutcome::Open { rtt } => probe.baseline = Some(rtt),
        // Соединение не встало вовсе — рукопожатие даже не начнётся.
        // Гонять три пробы по тайм-ауту каждая незачем: результат уже известен,
        // а человек ждал бы лишние полминуты на каждой такой цели.
        _ => {
            let outcome = match connect {
                TcpOutcome::Refused { rtt } => tls::Outcome::Reset { after: rtt },
                _ => tls::Outcome::Timeout,
            };
            probe.real_sni = Some(outcome.clone());
            probe.neutral_sni = Some(outcome);
            return probe;
        }
    }

    // У цели-адреса имени нет: обе пробы шли бы с одним и тем же нейтральным
    // именем и сравнивать было бы нечего.
    let sni = match target.kind {
        Kind::Domain => domain,
        Kind::Address(_) => NEUTRAL_SNI,
    };

    let real = tls::probe(address, 443, sni, tls::Delivery::Whole, PROBE_TIMEOUT);
    let broken = real.is_broken();
    probe.real_sni = Some(real);
    probe.neutral_sni = Some(tls::probe(
        address,
        443,
        NEUTRAL_SNI,
        tls::Delivery::Whole,
        PROBE_TIMEOUT,
    ));

    // Разделять пакет имеет смысл только там, где целый не прошёл.
    if broken && target.is_domain() {
        probe.split_sni = Some(tls::probe(
            address,
            443,
            domain,
            tls::Delivery::Split,
            PROBE_TIMEOUT,
        ));
    }

    probe
}

/// Перехватывает ли провайдер обращения к чужим DNS-серверам.
///
/// Спрашиваем адрес, на котором заведомо никого нет. Настоящего ответа быть
/// не может — если он пришёл, значит запрос перехватили по дороге.
fn check_dns_interception(rep: &Reporter, link: &l1_l2::LinkInfo) {
    let check = CheckResult::new(
        "l7.dns.intercept",
        Layer::L7Application,
        NodeId::Provider,
        "Перехват DNS-запросов",
    );

    let outcome = dns::query_udp(
        IpAddr::V4(NOWHERE_RESOLVER),
        "example.com",
        Duration::from_secs(2),
    );

    let check = match outcome {
        Ok(answer) => check
            .finish(
                Status::Warn,
                format!(
                    "Провайдер перехватывает запросы к DNS-серверам: ответ пришёл от адреса \
                     {NOWHERE_RESOLVER}, где никакого сервера нет. Значит смена DNS в настройках \
                     ничего не изменит — отвечать всё равно будет провайдер."
                ),
                format!(
                    "Запрос к {NOWHERE_RESOLVER}:53 получил ответ: {}. Адрес принадлежит \
                     диапазону для документации, работающего резолвера там быть не может.",
                    answer.describe()
                ),
            )
            .with_evidence(format!("ответ от {NOWHERE_RESOLVER}: {}", answer.describe())),
        Err(_) => check.finish(
            Status::Ok,
            "Запросы к DNS-серверам не перехватываются: можно менять DNS в настройках, \
             и это будет иметь смысл.",
            format!(
                "Запрос к {NOWHERE_RESOLVER}:53 остался без ответа, как и должно быть. \
                 Системные серверы: {}.",
                if link.dns_servers.is_empty() {
                    "не сообщены".to_string()
                } else {
                    link.dns_servers
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            ),
        ),
    };
    rep.check(check);
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
    transit: &'a censorship::Transit,
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

    // Фильтрация по имени сайта — отдельный исход: интернет при этом работает,
    // и говорить «интернета нет» было бы неправдой.
    if o.transit.is_confident() {
        return Diagnosis {
            headline: "Интернет работает, но часть сайтов блокируют".into(),
            simple: format!(
                "{} Само подключение исправно: роутер, провайдер и интернет отвечают.",
                o.transit.simple()
            ),
            expert: o.transit.expert(),
            actions: tunnel_note(vec![
                "Это не поломка вашего оборудования — перезагрузка роутера не поможет.".into(),
                "Сайты, которые не открываются, перечислены в разделе «Уровни OSI».".into(),
            ]),
            break_edge: Some((NodeId::Dpi, NodeId::Target)),
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
    if o.transit.has_signals() {
        actions.push(
            "Один сайт не открывается из-за своего имени. Одного случая мало для выводов — \
             посмотрите подробности в разделе «Уровни OSI»."
                .to_string(),
        );
    }

    // Вывод «блокировок нет» при работающем обходе был бы неправдой: обход
    // для того и запущен, чтобы фильтр не сработал.
    let hidden_by = o.bypass.dpi_bypass_name();
    if let Some(tool) = hidden_by {
        actions.push(format!(
            "Чтобы узнать, есть ли блокировки на самом деле, отключите {tool} и повторите \
             проверку."
        ));
    }

    let clean = o.bypass.is_empty() && !o.transit.has_signals();

    Diagnosis {
        headline: "Интернет работает".into(),
        simple: match hidden_by {
            Some(tool) => format!(
                "Подключение, роутер, выход в интернет и сайты — всё отвечает. Но у вас \
                 работает {tool}, поэтому проверить, блокирует ли что-то провайдер, \
                 сейчас нельзя."
            ),
            None => "Подключение, роутер, выход в интернет, имена сайтов и сами сайты — \
                     всё отвечает."
                .to_string(),
        },
        expert: format!(
            "L1–L7 в норме, маршрут построен на {} узлов. {}{}",
            o.route.hops.len(),
            o.transit.expert(),
            if hidden_by.is_some() {
                " Отрицательный вывод о блокировках недостоверен: активен обход DPI."
            } else {
                ""
            }
        ),
        actions: tunnel_note(actions),
        break_edge: None,
        status: if clean { Status::Ok } else { Status::Warn },
    }
}
