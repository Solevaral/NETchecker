//! Обнаружение средств обхода блокировок и туннелей.
//!
//! Это не украшение отчёта, а условие его правдивости. Если на компьютере
//! работает VPN или zapret, все остальные проверки описывают уже обойдённый
//! канал, а не тот, что даёт провайдер. Пользователь должен видеть это первым,
//! иначе он сделает неверный вывод из верных цифр.
//!
//! Ищем тремя независимыми способами: по запущенным процессам, по сетевым
//! интерфейсам и по локальным портам, на которых кто-то слушает. Ни один из
//! них не даёт стопроцентной уверенности, поэтому в отчёт всегда идёт не голый
//! вывод, а признак, по которому он сделан.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use netdev::Interface;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

use crate::engine::probe::tcp_connect;

/// Какого рода средство найдено.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassKind {
    /// Обход DPI, работающий с трафиком напрямую: zapret, GoodbyeDPI и родня.
    DpiBypass,
    /// Туннель, через который уходит весь трафик.
    Vpn,
    /// Локальный прокси: трафик идёт через него только у тех приложений,
    /// которые о нём знают.
    Proxy,
}

impl BypassKind {
    pub fn title(self) -> &'static str {
        match self {
            BypassKind::DpiBypass => "Обход блокировок",
            BypassKind::Vpn => "VPN-туннель",
            BypassKind::Proxy => "Локальный прокси",
        }
    }
}

/// Насколько уверенно можно сказать, что средство влияет на трафик.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// Средство найдено, но неизвестно, идёт ли через него трафик.
    Found,
    /// Подтверждено делом: туннель несёт маршрут по умолчанию,
    /// либо прокси принял соединение.
    Active,
}

/// Одна находка.
#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: BypassKind,
    /// Как это называется у пользователя: «WireGuard», «zapret», «прокси на порту 1080».
    pub name: String,
    /// По какому признаку нашли — идёт в доказательства как есть.
    pub evidence: String,
    pub confidence: Confidence,
}

/// Итог: что найдено и меняет ли это смысл остальных проверок.
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    /// Уходит ли весь трафик мимо обычного канала. Только в этом случае
    /// остальные выводы описывают не подключение пользователя.
    pub fn traffic_is_tunneled(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.kind == BypassKind::Vpn && f.confidence == Confidence::Active)
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Короткая сводка для строки отчёта.
    pub fn summary(&self) -> String {
        if self.findings.is_empty() {
            return "Средств обхода и туннелей не обнаружено.".to_string();
        }
        let names: Vec<&str> = self.findings.iter().map(|f| f.name.as_str()).collect();
        format!("Найдено: {}.", names.join(", "))
    }
}

/// Известные процессы. Список заведомо неполный — поэтому совпадение ищется
/// по вхождению подстроки, а не по точному имени, и всегда попадает
/// в доказательства вместе с настоящим именем процесса.
const PROCESS_MARKERS: &[(&str, BypassKind, &str)] = &[
    // zapret и его сборки под Windows
    ("winws", BypassKind::DpiBypass, "zapret (winws)"),
    ("nfqws", BypassKind::DpiBypass, "zapret (nfqws)"),
    ("tpws", BypassKind::DpiBypass, "zapret (tpws)"),
    ("zapret", BypassKind::DpiBypass, "zapret"),
    ("goodbyedpi", BypassKind::DpiBypass, "GoodbyeDPI"),
    ("byedpi", BypassKind::DpiBypass, "ByeDPI"),
    // VPN-клиенты
    ("wireguard", BypassKind::Vpn, "WireGuard"),
    ("openvpn", BypassKind::Vpn, "OpenVPN"),
    ("amneziavpn", BypassKind::Vpn, "AmneziaVPN"),
    ("outline", BypassKind::Vpn, "Outline"),
    ("tailscale", BypassKind::Vpn, "Tailscale"),
    ("nordvpn", BypassKind::Vpn, "NordVPN"),
    ("protonvpn", BypassKind::Vpn, "Proton VPN"),
    ("windscribe", BypassKind::Vpn, "Windscribe"),
    // Прокси-клиенты
    ("tg-ws-proxy", BypassKind::Proxy, "tg-ws-proxy"),
    ("tgwsproxy", BypassKind::Proxy, "tg-ws-proxy"),
    ("mtproto", BypassKind::Proxy, "MTProto-прокси"),
    ("xray", BypassKind::Proxy, "Xray"),
    ("v2ray", BypassKind::Proxy, "V2Ray"),
    ("sing-box", BypassKind::Proxy, "sing-box"),
    ("nekoray", BypassKind::Proxy, "NekoRay"),
    ("hiddify", BypassKind::Proxy, "Hiddify"),
    ("clash", BypassKind::Proxy, "Clash"),
];

/// Порты, на которых обычно слушают локальные прокси.
///
/// Проверка честная: если на порт удалось установить соединение, значит там
/// действительно кто-то есть и он работает, а не просто прописан в настройках.
const PROXY_PORTS: &[(u16, &str)] = &[
    (1080, "SOCKS5"),
    (1081, "SOCKS5"),
    (2080, "SOCKS5"),
    (8080, "HTTP-прокси"),
    (8081, "HTTP-прокси"),
    (9050, "Tor"),
    (10808, "Xray/V2Ray SOCKS"),
    (10809, "Xray/V2Ray HTTP"),
];

/// Полная проверка. `interfaces` берутся из уже собранных на уровне L1–L2,
/// чтобы не опрашивать систему дважды.
pub fn detect(interfaces: &[Interface], default_is_tunnel: bool) -> Report {
    let mut findings = Vec::new();

    findings.extend(scan_processes());
    findings.extend(scan_interfaces(interfaces, default_is_tunnel));
    findings.extend(scan_proxy_ports());

    dedup(&mut findings);
    Report { findings }
}

fn scan_processes() -> Vec<Finding> {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing(),
    );

    let mut found = Vec::new();
    for process in system.processes().values() {
        let raw = process.name().to_string_lossy().to_lowercase();
        for (marker, kind, name) in PROCESS_MARKERS {
            if raw.contains(marker) {
                found.push(Finding {
                    kind: *kind,
                    name: (*name).to_string(),
                    evidence: format!("запущен процесс {}", process.name().to_string_lossy()),
                    confidence: Confidence::Found,
                });
                break;
            }
        }
    }
    found
}

/// Туннельный интерфейс — самый надёжный признак VPN. Если через него ещё
/// и уходит маршрут по умолчанию, значит трафик действительно идёт мимо
/// обычного канала, а не просто поднят простаивающий туннель.
fn scan_interfaces(interfaces: &[Interface], default_is_tunnel: bool) -> Vec<Finding> {
    interfaces
        .iter()
        .filter(|i| i.is_up() && !i.is_loopback() && is_tunnel(i))
        .map(|i| {
            let label = i
                .friendly_name
                .clone()
                .or_else(|| i.description.clone())
                .unwrap_or_else(|| i.name.clone());
            Finding {
                kind: BypassKind::Vpn,
                name: format!("Туннель «{label}»"),
                evidence: format!(
                    "поднят туннельный интерфейс {label}{}",
                    if default_is_tunnel {
                        ", через него идёт маршрут по умолчанию"
                    } else {
                        ", но маршрут по умолчанию идёт мимо него"
                    }
                ),
                confidence: if default_is_tunnel {
                    Confidence::Active
                } else {
                    Confidence::Found
                },
            }
        })
        .collect()
}

fn scan_proxy_ports() -> Vec<Finding> {
    PROXY_PORTS
        .iter()
        .filter_map(|(port, label)| {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), *port);
            tcp_connect(addr, Duration::from_millis(150))
                .is_open()
                .then(|| Finding {
                    kind: BypassKind::Proxy,
                    name: format!("прокси на порту {port}"),
                    evidence: format!("порт 127.0.0.1:{port} принимает соединения ({label})"),
                    confidence: Confidence::Active,
                })
        })
        .collect()
}

fn is_tunnel(iface: &Interface) -> bool {
    if iface.is_tun() {
        return true;
    }
    let haystack = format!(
        "{} {} {}",
        iface.name,
        iface.friendly_name.clone().unwrap_or_default(),
        iface.description.clone().unwrap_or_default()
    )
    .to_lowercase();
    ["wireguard", "openvpn", "tap-windows", "wintun", "tun", "amnezia"]
        .iter()
        .any(|m| haystack.contains(m))
}

/// Одно и то же средство легко находится дважды — например, и по процессу,
/// и по интерфейсу. Оставляем находку с более сильным признаком.
fn dedup(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(b.confidence.cmp(&a.confidence))
    });
    findings.dedup_by(|a, b| a.name == b.name);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(name: &str, kind: BypassKind, confidence: Confidence) -> Finding {
        Finding {
            kind,
            name: name.to_string(),
            evidence: String::new(),
            confidence,
        }
    }

    #[test]
    fn duplicates_keep_the_stronger_signal() {
        let mut list = vec![
            finding("WireGuard", BypassKind::Vpn, Confidence::Found),
            finding("WireGuard", BypassKind::Vpn, Confidence::Active),
        ];
        dedup(&mut list);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].confidence, Confidence::Active);
    }

    /// Поднятый, но неиспользуемый туннель не должен объявляться причиной,
    /// по которой остальным цифрам нельзя верить.
    #[test]
    fn idle_tunnel_does_not_count_as_tunneled_traffic() {
        let report = Report {
            findings: vec![finding("Туннель", BypassKind::Vpn, Confidence::Found)],
        };
        assert!(!report.traffic_is_tunneled());

        let report = Report {
            findings: vec![finding("Туннель", BypassKind::Vpn, Confidence::Active)],
        };
        assert!(report.traffic_is_tunneled());
    }

    #[test]
    fn empty_report_says_so_plainly() {
        assert!(Report::default().summary().contains("не обнаружено"));
    }
}
