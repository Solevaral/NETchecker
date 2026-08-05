//! Проверки физического и канального уровней: есть ли рабочий сетевой
//! интерфейс, получен ли адрес, виден ли шлюз.
//!
//! Всё, что здесь выясняется, определяет смысл всех последующих проверок:
//! если кабель не воткнут, бессмысленно рассказывать про DNS.

use std::net::{IpAddr, Ipv4Addr};

use netdev::interface::types::InterfaceType;
use netdev::Interface;

use crate::bus::Reporter;
use crate::model::{CheckResult, Layer, NodeId, Status};

/// Сведения о подключении, которые нужны следующим уровням.
pub struct LinkInfo {
    /// Активный интерфейс, если он вообще нашёлся.
    pub interface: Option<Interface>,
    /// Адрес шлюза — это и есть «роутер» на схеме.
    pub gateway: Option<IpAddr>,
    /// DNS-серверы, выданные системой.
    pub dns_servers: Vec<IpAddr>,
    /// Похоже, что трафик идёт через VPN — результаты будут про VPN, а не про канал.
    pub through_vpn: bool,
}

pub fn run(rep: &Reporter) -> LinkInfo {
    let interfaces = netdev::get_interfaces();
    let default = netdev::get_default_interface().ok();

    let vpn = interfaces
        .iter()
        .find(|i| i.is_up() && !i.is_loopback() && is_vpn_like(i));

    // Проверка L1: есть ли поднятый физический интерфейс с линком.
    let usable: Vec<&Interface> = interfaces
        .iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .collect();

    let l1 = CheckResult::new(
        "l1.link",
        Layer::L1Physical,
        NodeId::Pc,
        "Сетевой адаптер и линк",
    );
    let l1 = if usable.is_empty() {
        l1.finish(
            Status::Fail,
            "Компьютер вообще не видит рабочего сетевого подключения. Проверьте, воткнут ли \
             кабель и включён ли Wi-Fi.",
            "Ни одного не-loopback интерфейса в состоянии UP.",
        )
    } else {
        let names: Vec<String> = usable.iter().map(|i| describe(i)).collect();
        l1.finish(
            Status::Ok,
            format!(
                "Сетевое подключение есть: {}.",
                names.first().cloned().unwrap_or_default()
            ),
            format!("Активных интерфейсов: {}.", usable.len()),
        )
        .with_evidence(names.join("\n"))
    };
    rep.check(l1);

    let Some(iface) = default.or_else(|| usable.first().map(|i| (*i).clone())) else {
        rep.check(
            CheckResult::new("l2.addr", Layer::L2Link, NodeId::Pc, "IP-адрес").finish(
                Status::Skipped,
                "Проверка адреса пропущена: нет активного подключения.",
                "Нет интерфейса — проверять нечего.",
            ),
        );
        rep.check(
            CheckResult::new("l2.gateway", Layer::L2Link, NodeId::Router, "Роутер").finish(
                Status::Skipped,
                "Проверка роутера пропущена: нет активного подключения.",
                "Нет интерфейса — шлюз не определить.",
            ),
        );
        return LinkInfo {
            interface: None,
            gateway: None,
            dns_servers: Vec::new(),
            through_vpn: vpn.is_some(),
        };
    };

    rep.node(
        NodeId::Pc,
        describe(&iface),
        iface.ipv4.first().map(|n| n.addr().to_string()),
    );

    // Проверка адреса: раздельно разбираем «адреса нет», APIPA и нормальный случай.
    let addr_check = CheckResult::new("l2.addr", Layer::L2Link, NodeId::Pc, "IP-адрес компьютера");
    let v4 = iface.ipv4.first().map(|n| n.addr());
    let addr_check = match v4 {
        None => addr_check.finish(
            Status::Fail,
            "Компьютер не получил адрес в сети. Обычно помогает перезагрузка роутера.",
            "На интерфейсе нет ни одного адреса IPv4.",
        ),
        Some(a) if is_apipa(a) => addr_check.finish(
            Status::Fail,
            "Роутер не выдал компьютеру адрес, и Windows назначила временный. \
             Связи с роутером фактически нет.",
            format!("Адрес {a} из диапазона APIPA 169.254.0.0/16 — DHCP не ответил."),
        ),
        Some(a) => addr_check
            .finish(
                Status::Ok,
                format!("Компьютеру выдан адрес {a} — с роутером он общается."),
                format!(
                    "IPv4 {}/{}, DHCP: {}.",
                    a,
                    iface.ipv4.first().map(|n| n.prefix_len()).unwrap_or(0),
                    match iface.dhcp_v4_enabled {
                        Some(true) => "включён",
                        Some(false) => "выключен, адрес задан вручную",
                        None => "неизвестно",
                    }
                ),
            )
            .with_evidence(format!(
                "MAC: {}",
                iface
                    .mac_addr
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "неизвестен".into())
            )),
    };
    rep.check(addr_check);

    // Проверка шлюза: наличие маршрута по умолчанию.
    let gateway = iface
        .gateway
        .as_ref()
        .and_then(|g| g.ipv4.first().map(|a| IpAddr::V4(*a)));

    let gw_check = CheckResult::new("l2.gateway", Layer::L2Link, NodeId::Router, "Роутер и маршрут");
    let gw_check = match gateway {
        Some(gw) => {
            rep.node(NodeId::Router, "маршрут по умолчанию", Some(gw.to_string()));
            gw_check.finish(
                Status::Ok,
                format!("Роутер найден по адресу {gw}."),
                format!(
                    "Шлюз по умолчанию {gw}, MAC {}.",
                    iface
                        .gateway
                        .as_ref()
                        .map(|g| g.mac_addr.to_string())
                        .unwrap_or_else(|| "неизвестен".into())
                ),
            )
        }
        None => {
            rep.node(NodeId::Router, "не найден", None);
            gw_check.finish(
                Status::Fail,
                "Компьютер не знает, через какое устройство выходить в интернет. \
                 Обычно это значит, что роутер недоступен.",
                "Нет маршрута по умолчанию (default gateway).",
            )
        }
    };
    rep.check(gw_check);

    // Предупреждение про VPN: без него все выводы ниже будут вводить в заблуждение.
    if let Some(vpn_iface) = vpn {
        rep.check(
            CheckResult::new("l2.vpn", Layer::L2Link, NodeId::Pc, "Активный VPN").finish(
                Status::Warn,
                "Похоже, включён VPN. Результаты проверки описывают канал через VPN, \
                 а не ваше настоящее подключение. Для проверки провайдера отключите VPN.",
                format!("Обнаружен туннельный интерфейс: {}.", describe(vpn_iface)),
            ),
        );
    }

    LinkInfo {
        dns_servers: iface.dns_servers.clone(),
        gateway,
        through_vpn: vpn.is_some(),
        interface: Some(iface),
    }
}

/// Человекочитаемое имя интерфейса: на Windows системное имя — это GUID,
/// поэтому предпочитаем «дружественное».
fn describe(iface: &Interface) -> String {
    let name = iface
        .friendly_name
        .clone()
        .or_else(|| iface.description.clone())
        .unwrap_or_else(|| iface.name.clone());
    format!("{name} ({})", iface.if_type.name())
}

/// Туннельные адаптеры VPN. Точного признака нет, ориентируемся на тип
/// интерфейса и характерные имена клиентов.
fn is_vpn_like(iface: &Interface) -> bool {
    if iface.is_tun() || iface.if_type == InterfaceType::Tunnel {
        return true;
    }
    let haystack = format!(
        "{} {} {}",
        iface.name,
        iface.friendly_name.clone().unwrap_or_default(),
        iface.description.clone().unwrap_or_default()
    )
    .to_lowercase();
    ["wireguard", "openvpn", "tap-windows", "tun", "wintun"]
        .iter()
        .any(|m| haystack.contains(m))
}

/// Адрес, который система назначает сама, когда DHCP не ответил.
fn is_apipa(addr: Ipv4Addr) -> bool {
    addr.octets()[0] == 169 && addr.octets()[1] == 254
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apipa_range_is_recognised() {
        assert!(is_apipa(Ipv4Addr::new(169, 254, 13, 7)));
        assert!(!is_apipa(Ipv4Addr::new(192, 168, 1, 10)));
        assert!(!is_apipa(Ipv4Addr::new(169, 253, 1, 1)));
    }
}
