//! Оркестратор диагностики.
//!
//! Проверки идут снизу вверх по модели OSI, и порядок здесь не косметический:
//! вывод верхнего уровня имеет смысл только в свете нижнего. Если роутер
//! недоступен, «сайт не открывается» — не диагноз, а следствие.
//!
//! Всё выполняется в отдельном потоке и рапортует в UI через [`Reporter`].

pub mod l1_l2;
pub mod probe;

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::thread;
use std::time::Duration;

use crate::bus::{EngineEvent, Reporter};
use crate::model::{CheckResult, Diagnosis, Layer, NodeId, Status};
use crate::privileged::Capabilities;

use probe::{ms, tcp_connect, TcpOutcome};

/// Опорные точки интернета. Разные операторы и разные страны — если недоступны
/// сразу все, дело почти наверняка не в них.
const ANCHORS: [(&str, IpAddr); 3] = [
    ("Cloudflare", IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1))),
    ("Google", IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))),
    ("Яндекс", IpAddr::V4(std::net::Ipv4Addr::new(77, 88, 8, 8))),
];

/// Домены для проверки прикладного уровня.
const SITES: [&str; 2] = ["ya.ru", "example.com"];

const TIMEOUT: Duration = Duration::from_secs(4);

/// Запускает диагностику в фоне. Вызывающий продолжает рисовать окно.
pub fn spawn(caps: Capabilities, rep: Reporter) {
    thread::spawn(move || run(caps, &rep));
}

fn run(caps: Capabilities, rep: &Reporter) {
    // Число шагов фиксировано и совпадает с количеством вызовов progress ниже.
    rep.send(EngineEvent::Started { total: 4 });

    rep.progress(0, "Проверяю сетевой адаптер и роутер…");
    let link = l1_l2::run(rep);

    rep.progress(1, "Проверяю доступность роутера…");
    let router_alive = check_router(rep, link.gateway);

    rep.progress(2, "Проверяю выход в интернет…");
    let anchors_ok = check_anchors(rep, caps);

    rep.progress(3, "Проверяю имена сайтов и соединение с ними…");
    let dns_ok = check_dns_and_sites(rep, &link);

    rep.progress(4, "Готово");
    rep.send(EngineEvent::Finished(Box::new(verdict(
        &link,
        router_alive,
        anchors_ok,
        dns_ok,
    ))));
}

/// Отвечает ли сам роутер. Без ICMP судим по TCP: и открытый порт, и явный
/// отказ одинаково доказывают, что устройство на связи.
fn check_router(rep: &Reporter, gateway: Option<IpAddr>) -> Option<bool> {
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

    let mut evidence = Vec::new();
    let mut alive = false;
    for port in [80u16, 443, 53] {
        let outcome = tcp_connect(SocketAddr::new(gw, port), Duration::from_millis(800));
        evidence.push(format!("TCP {gw}:{port} — {}", outcome.describe()));
        if matches!(outcome, TcpOutcome::Open { .. } | TcpOutcome::Refused { .. }) {
            alive = true;
        }
    }

    let check = CheckResult::new("l3.router", Layer::L3Network, NodeId::Router, "Отклик роутера");
    let check = if alive {
        check.finish(
            Status::Ok,
            format!("Роутер {gw} отвечает — до него связь есть."),
            "Роутер ответил на TCP-пробу (соединением или явным отказом).",
        )
    } else {
        check.finish(
            Status::Warn,
            format!(
                "Роутер {gw} не ответил на пробу. Это не всегда поломка: часть роутеров \
                 намеренно молчит. Смотрите проверки ниже."
            ),
            "Ни один из портов 80/443/53 не дал ответа. Точный вывод даст ICMP-проверка.",
        )
    };
    rep.check(evidence.into_iter().fold(check, |c, e| c.with_evidence(e)));

    Some(alive)
}

/// Доступны ли опорные узлы интернета.
fn check_anchors(rep: &Reporter, caps: Capabilities) -> bool {
    let mut reachable = Vec::new();
    let mut evidence = Vec::new();

    for (name, ip) in ANCHORS {
        let outcome = tcp_connect(SocketAddr::new(ip, 443), TIMEOUT);
        evidence.push(format!("{name} {ip}:443 — {}", outcome.describe()));
        if outcome.is_open() {
            reachable.push(name);
        }
    }

    let ok = !reachable.is_empty();
    let check = CheckResult::new(
        "l4.anchors",
        Layer::L4Transport,
        NodeId::Internet,
        "Связь с интернетом",
    );
    let check = if ok {
        check.finish(
            Status::Ok,
            format!(
                "Интернет доступен: отвечают {}.",
                reachable.join(", ")
            ),
            format!("Установлены TCP-соединения на 443 к {} из {} опорных узлов.", reachable.len(), ANCHORS.len()),
        )
    } else {
        check.finish(
            Status::Fail,
            "Ни один сервер в интернете не отвечает. Дальше локальной сети трафик не уходит.",
            "Все опорные узлы не ответили на TCP-443.",
        )
    };

    let check = check.with_evidence(format!(
        "Режим замеров: {} — {}",
        caps.icmp.title(),
        caps.icmp.explanation()
    ));
    rep.check(evidence.into_iter().fold(check, |c, e| c.with_evidence(e)));

    ok
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

/// Сведение наблюдений в один понятный вывод.
///
/// Правил намеренно немного: это первый этап, и лучше честно сказать
/// «связь есть, деталей пока нет», чем выдумать точный диагноз.
fn verdict(
    link: &l1_l2::LinkInfo,
    router_alive: Option<bool>,
    anchors_ok: bool,
    dns_ok: bool,
) -> Diagnosis {
    if link.interface.is_none() {
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

    if link.gateway.is_none() {
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

    if !anchors_ok {
        let simple = if router_alive == Some(true) {
            "Роутер работает, но дальше него трафик не проходит. Похоже, интернет не даёт \
             провайдер."
        } else {
            "Локальная сеть есть, но выхода в интернет нет."
        };
        return Diagnosis {
            headline: "Интернета нет за роутером".into(),
            simple: simple.into(),
            expert: "Ни один опорный узел не ответил на TCP-443 при живом шлюзе.".into(),
            actions: vec![
                "Перезагрузите роутер.".into(),
                "Проверьте баланс и статус услуги у провайдера.".into(),
                "Если интернет мобильный — проверьте, не отключён ли он в вашем районе.".into(),
            ],
            break_edge: Some((NodeId::Router, NodeId::Provider)),
            status: Status::Fail,
        };
    }

    if !dns_ok {
        return Diagnosis {
            headline: "Интернет есть, но имена сайтов не работают".into(),
            simple: "Соединения с интернетом проходят, а вот превратить имя сайта в адрес \
                     не получается. Обычно виноват DNS-сервер."
                .into(),
            expert: "Опорные узлы доступны по IP, системный резолвер записей не вернул.".into(),
            actions: vec![
                "Попробуйте прописать DNS 1.1.1.1 или 77.88.8.8.".into(),
                "Перезагрузите роутер — часто он же и раздаёт DNS.".into(),
            ],
            break_edge: Some((NodeId::Internet, NodeId::Target)),
            status: Status::Fail,
        };
    }

    let mut actions = Vec::new();
    if link.through_vpn {
        actions.push(
            "Включён VPN: чтобы проверить собственный канал, отключите его и повторите."
                .to_string(),
        );
    }

    Diagnosis {
        headline: "Интернет работает".into(),
        simple: "Подключение, роутер, выход в интернет и имена сайтов — всё отвечает.".into(),
        expert: "L1–L4 и разрешение имён в норме. Проверки на блокировки, подмену DNS \
                 и замедление появятся на следующих этапах."
            .into(),
        actions,
        break_edge: None,
        status: Status::Ok,
    }
}
