//! Трассировка маршрута и разбор того, что она показала.
//!
//! Сам по себе список адресов ничего не объясняет. Ценность в том, *где*
//! обрывается путь: внутри квартиры, у провайдера или уже на транзите. Поэтому
//! каждый хоп сразу относится к участку сети, а не остаётся просто адресом.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::engine::icmp::{Pinger, ReplyKind};

/// Максимальная длина маршрута. Дальше 30 хопов в реальной жизни не уходит
/// ничего, а лишние попытки — это лишние секунды ожидания.
pub const MAX_HOPS: u8 = 30;

/// Сколько проб на один хоп. Три — компромисс: одиночная проба слишком часто
/// теряется на узлах, которые ограничивают частоту ICMP-ответов.
const PROBES_PER_HOP: usize = 3;

const PROBE_TIMEOUT: Duration = Duration::from_millis(1200);

/// К какому участку сети относится узел.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Segment {
    /// Наша собственная сеть: роутер, к которому подключён компьютер.
    Local,
    /// Тоже частный адрес, но из другой сети: второй роутер в цепочке,
    /// оборудование в доме или служебная сеть провайдера. Провайдером
    /// такой узел называть нельзя — снаружи его не существует.
    PrivateTransit,
    /// Адрес из 100.64.0.0/10 — провайдер раздаёт «серый» адрес через CGNAT.
    Cgnat,
    /// Публичный адрес: здесь начинается настоящий интернет.
    Public,
}

impl Segment {
    pub fn title(self) -> &'static str {
        match self {
            Segment::Local => "ваша сеть",
            Segment::PrivateTransit => "частная сеть по пути (ещё один роутер или сеть дома)",
            Segment::Cgnat => "сеть провайдера (общий адрес, CGNAT)",
            Segment::Public => "провайдер и дальше",
        }
    }

    /// Вышли ли мы за пределы частных сетей. Только такой узел имеет смысл
    /// показывать пользователю как «провайдер».
    pub fn is_external(self) -> bool {
        matches!(self, Segment::Cgnat | Segment::Public)
    }
}

/// Время отклика человеческим языком.
///
/// Windows отдаёт задержку целыми миллисекундами, поэтому у соседнего роутера
/// она честно равна нулю. Писать «0 мс» нельзя: это читается как «мгновенно»
/// или как отсутствие замера.
pub fn format_rtt(rtt: Duration) -> String {
    if rtt.as_millis() == 0 {
        "меньше 1 мс".to_string()
    } else {
        format!("{} мс", rtt.as_millis())
    }
}

/// Один узел на пути.
#[derive(Debug, Clone)]
pub struct Hop {
    /// Номер, он же TTL, при котором узел откликнулся.
    pub ttl: u8,
    /// Адрес узла. `None` — узел промолчал.
    pub address: Option<IpAddr>,
    /// Лучшее время отклика из проб.
    pub rtt: Option<Duration>,
    /// Сколько проб из [`PROBES_PER_HOP`] осталось без ответа.
    pub lost: usize,
    pub segment: Option<Segment>,
    /// Узел явно отказал в пропуске трафика.
    pub prohibited: bool,
}

impl Hop {
    /// Строка для отчёта в привычном для трассировки виде.
    pub fn describe(&self) -> String {
        match self.address {
            Some(addr) => {
                let rtt = self.rtt.map(format_rtt).unwrap_or_else(|| "—".into());
                let segment = self
                    .segment
                    .map(|s| format!(", {}", s.title()))
                    .unwrap_or_default();
                let lost = if self.lost > 0 {
                    format!(", потеряно проб: {}/{}", self.lost, PROBES_PER_HOP)
                } else {
                    String::new()
                };
                format!("{:>2}. {addr} — {rtt}{segment}{lost}", self.ttl)
            }
            None => format!("{:>2}. нет ответа", self.ttl),
        }
    }
}

/// Итог трассировки.
#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub hops: Vec<Hop>,
    /// Дошли ли до цели.
    pub reached: bool,
    /// Первый узел за пределами домашней сети — это и есть «провайдер»
    /// с точки зрения пользователя.
    pub first_external: Option<Hop>,
}

impl Trace {
    /// Последний узел, который вообще откликнулся.
    pub fn last_responding(&self) -> Option<&Hop> {
        self.hops.iter().rev().find(|h| h.address.is_some())
    }

    /// Сколько хопов подряд промолчало в конце маршрута.
    ///
    /// Один-два молчащих хопа — обычное дело, узлы часто не отвечают на ICMP.
    /// А вот длинный молчащий хвост означает, что дальше пакеты просто не идут.
    pub fn silent_tail(&self) -> usize {
        self.hops
            .iter()
            .rev()
            .take_while(|h| h.address.is_none())
            .count()
    }

    /// Узел, на котором путь оборвался, если он оборвался.
    pub fn break_after(&self) -> Option<&Hop> {
        if self.reached {
            return None;
        }
        self.last_responding()
    }
}

/// Прогоняет трассировку до цели.
///
/// `on_hop` вызывается после каждого узла — трассировка занимает секунды,
/// и показывать её надо по мере появления, а не одним куском в конце.
pub fn run(
    pinger: &Pinger,
    target: Ipv4Addr,
    local_prefixes: &[Ipv4Addr],
    mut on_hop: impl FnMut(&Hop),
) -> Trace {
    let mut trace = Trace::default();

    for ttl in 1..=MAX_HOPS {
        let mut hop = Hop {
            ttl,
            address: None,
            rtt: None,
            lost: 0,
            segment: None,
            prohibited: false,
        };
        let mut reached = false;

        for _ in 0..PROBES_PER_HOP {
            let reply = pinger.ping(target, ttl, PROBE_TIMEOUT);
            match reply.kind {
                ReplyKind::Echo => {
                    reached = true;
                    absorb(&mut hop, reply.from, reply.rtt);
                }
                ReplyKind::TtlExpired => absorb(&mut hop, reply.from, reply.rtt),
                ReplyKind::Prohibited => {
                    hop.prohibited = true;
                    absorb(&mut hop, reply.from, reply.rtt);
                }
                ReplyKind::Unreachable | ReplyKind::TooBig => {
                    absorb(&mut hop, reply.from, reply.rtt)
                }
                ReplyKind::Timeout | ReplyKind::Error => hop.lost += 1,
            }
        }

        if let Some(IpAddr::V4(addr)) = hop.address {
            hop.segment = Some(classify(addr, local_prefixes));
        }

        on_hop(&hop);

        let is_external = hop.segment.is_some_and(Segment::is_external);
        if is_external && trace.first_external.is_none() {
            trace.first_external = Some(hop.clone());
        }

        trace.hops.push(hop);

        if reached {
            trace.reached = true;
            break;
        }

        // Пять молчащих узлов подряд — дальше идти незачем, там стена.
        if trace.silent_tail() >= 5 {
            break;
        }
    }

    trace
}

/// Первый ответ задаёт адрес хопа, последующие только уточняют лучшее время.
fn absorb(hop: &mut Hop, from: Option<IpAddr>, rtt: Option<Duration>) {
    if hop.address.is_none() {
        hop.address = from;
    }
    if let Some(rtt) = rtt {
        hop.rtt = Some(match hop.rtt {
            Some(best) => best.min(rtt),
            None => rtt,
        });
    }
}

/// Относит адрес к участку сети.
///
/// Разделение «наша сеть / чужая частная / публичная» здесь важнее точности:
/// частный адрес на втором хопе — это почти всегда ещё один роутер в цепочке,
/// а вовсе не провайдер. Назвать его провайдером значило бы сказать человеку,
/// что трафик уже вышел в интернет, когда он ещё даже не покинул дом.
fn classify(addr: Ipv4Addr, local_prefixes: &[Ipv4Addr]) -> Segment {
    if is_cgnat(addr) {
        return Segment::Cgnat;
    }
    if local_prefixes.iter().any(|p| same_24(*p, addr)) {
        return Segment::Local;
    }
    if is_private(addr) {
        return Segment::PrivateTransit;
    }
    Segment::Public
}

/// Диапазон 100.64.0.0/10, который провайдеры используют для общих адресов.
fn is_cgnat(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 100 && (64..128).contains(&o[1])
}

/// Частные диапазоны по RFC 1918 плюс адреса самоназначения.
fn is_private(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    addr.is_private() || addr.is_link_local() || o[0] == 127
}

/// Грубое «та же сеть»: совпадают первые три октета.
///
/// Точную маску мы знаем только для своего интерфейса, а для соседних узлов —
/// нет, поэтому берём самое частое домашнее /24. Ошибка тут не критична:
/// она сдвинет подпись участка, но не вывод о месте обрыва.
fn same_24(a: Ipv4Addr, b: Ipv4Addr) -> bool {
    a.octets()[..3] == b.octets()[..3]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgnat_range_is_recognised() {
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 1)));
    }

    /// Второй роутер в цепочке нельзя объявлять провайдером: трафик до него
    /// ещё даже не вышел из дома.
    #[test]
    fn private_hop_is_neither_local_nor_provider() {
        let mine = [Ipv4Addr::new(192, 168, 20, 198)];
        assert_eq!(classify(Ipv4Addr::new(192, 168, 20, 1), &mine), Segment::Local);
        assert_eq!(
            classify(Ipv4Addr::new(192, 168, 1, 1), &mine),
            Segment::PrivateTransit
        );
        assert_eq!(classify(Ipv4Addr::new(10, 55, 0, 1), &mine), Segment::PrivateTransit);
        assert_eq!(classify(Ipv4Addr::new(46, 138, 240, 1), &mine), Segment::Public);
        assert!(!Segment::PrivateTransit.is_external());
        assert!(Segment::Public.is_external());
    }

    #[test]
    fn sub_millisecond_latency_is_not_shown_as_zero() {
        assert_eq!(format_rtt(Duration::from_millis(0)), "меньше 1 мс");
        assert_eq!(format_rtt(Duration::from_millis(24)), "24 мс");
    }

    #[test]
    fn silent_tail_counts_only_the_trailing_silence() {
        let hop = |addr: Option<IpAddr>| Hop {
            ttl: 1,
            address: addr,
            rtt: None,
            lost: 0,
            segment: None,
            prohibited: false,
        };
        let trace = Trace {
            hops: vec![
                hop(Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))),
                hop(None),
                hop(Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))),
                hop(None),
                hop(None),
            ],
            reached: false,
            first_external: None,
        };
        assert_eq!(trace.silent_tail(), 2);
        assert!(trace.break_after().is_some());
    }
}
