//! Отправка ICMP-эхо с управлением TTL — основа ping и трассировки.
//!
//! Транспорт выбирается под окружение (см. [`crate::privileged`]):
//!
//! * **Windows** — `IcmpSendEcho` из `iphlpapi`. Ключевая деталь: он работает
//!   без прав администратора, поэтому обычному пользователю доступна и полная
//!   трассировка, а не только TCP-пробы.
//! * **Unix** — сокет ICMP: датаграммный, если ядро разрешает
//!   непривилегированный ping, иначе raw.
//!
//! Наружу отдаётся один тип ответа [`Reply`], одинаковый для всех транспортов:
//! кто ответил, за сколько и что именно это был за ответ. Различать «дошло»,
//! «время жизни истекло по дороге» и «тишина» важнее самих замеров — на этом
//! строится поиск места обрыва.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::privileged::Capabilities;

/// Что именно вернулось на эхо-запрос.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyKind {
    /// Долетело до цели и она ответила.
    Echo,
    /// Промежуточный узел сообщил, что TTL истёк. Так и находятся хопы.
    TtlExpired,
    /// Узел или сеть недостижимы.
    Unreachable,
    /// Маршрутизатор запретил прохождение пакета административно.
    ///
    /// Разбирается только на Unix: `IcmpSendEcho` схлопывает все виды
    /// недостижимости в общие коды и этот случай отдельно не показывает.
    #[cfg_attr(windows, allow(dead_code))]
    Prohibited,
    /// Пакет не пролез из-за MTU и запрета фрагментации.
    TooBig,
    /// Ответа не было.
    Timeout,
    /// Отправить не удалось: ошибка на нашей стороне.
    Error,
}

impl ReplyKind {
    /// Дошёл ли пакет хоть до какого-то узла, который о себе сообщил.
    pub fn got_response(self) -> bool {
        !matches!(self, ReplyKind::Timeout | ReplyKind::Error)
    }

    pub fn describe(self) -> &'static str {
        match self {
            ReplyKind::Echo => "ответ получен",
            ReplyKind::TtlExpired => "истёк TTL на промежуточном узле",
            ReplyKind::Unreachable => "узел недостижим",
            ReplyKind::Prohibited => "прохождение запрещено административно",
            ReplyKind::TooBig => "пакет слишком велик, фрагментация запрещена",
            ReplyKind::Timeout => "ответа нет",
            ReplyKind::Error => "не удалось отправить запрос",
        }
    }
}

/// Ответ на один эхо-запрос.
#[derive(Debug, Clone)]
pub struct Reply {
    pub kind: ReplyKind,
    /// Кто ответил. При истёкшем TTL это адрес промежуточного узла.
    pub from: Option<IpAddr>,
    pub rtt: Option<Duration>,
    /// Подробность для строки доказательств, когда что-то пошло не так.
    pub detail: Option<String>,
}

impl Reply {
    fn timeout() -> Self {
        Self {
            kind: ReplyKind::Timeout,
            from: None,
            rtt: None,
            detail: None,
        }
    }

    fn error(detail: impl Into<String>) -> Self {
        Self {
            kind: ReplyKind::Error,
            from: None,
            rtt: None,
            detail: Some(detail.into()),
        }
    }
}

/// Отправитель эхо-запросов. Держит открытым дескриптор транспорта,
/// поэтому создаётся один раз на всю диагностику.
pub struct Pinger {
    inner: Inner,
}

impl Pinger {
    /// Возвращает `None`, если ICMP в этом окружении недоступен вовсе —
    /// тогда движок обязан честно пометить проверки как пропущенные.
    pub fn new(caps: Capabilities) -> Option<Self> {
        Inner::new(caps.icmp).map(|inner| Self { inner })
    }

    /// Один эхо-запрос с заданным TTL.
    ///
    /// TTL здесь не тонкая настройка, а рабочий инструмент: ставя его
    /// равным 1, 2, 3…, мы заставляем каждый следующий узел на пути
    /// представиться.
    pub fn ping(&self, target: Ipv4Addr, ttl: u8, timeout: Duration) -> Reply {
        self.inner.ping(target, ttl, timeout)
    }
}

/// Тип полезной нагрузки: 32 байта, как у системного `ping`, чтобы замеры
/// были сопоставимы с тем, что человек увидит в консоли.
const PAYLOAD: [u8; 32] = *b"netchecker icmp probe 0123456789";

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod backend {
    use super::{Reply, ReplyKind, PAYLOAD};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, ICMP_ECHO_REPLY, IP_OPTION_INFORMATION,
    };

    // Коды состояния из ipexport.h. Они стабильны десятилетиями и в
    // windows-sys не вынесены отдельными константами.
    const IP_SUCCESS: u32 = 0;
    const IP_DEST_NET_UNREACHABLE: u32 = 11002;
    const IP_DEST_HOST_UNREACHABLE: u32 = 11003;
    const IP_DEST_PROT_UNREACHABLE: u32 = 11004;
    const IP_DEST_PORT_UNREACHABLE: u32 = 11005;
    const IP_PACKET_TOO_BIG: u32 = 11009;
    const IP_REQ_TIMED_OUT: u32 = 11010;
    const IP_BAD_ROUTE: u32 = 11012;
    const IP_TTL_EXPIRED_TRANSIT: u32 = 11013;

    pub struct Inner {
        handle: HANDLE,
    }

    // Дескриптор ICMP используется только под общей блокировкой вызывающего
    // кода: каждый вызов IcmpSendEcho синхронный и самодостаточный.
    unsafe impl Send for Inner {}
    unsafe impl Sync for Inner {}

    impl Inner {
        pub fn new(_backend: crate::privileged::IcmpBackend) -> Option<Self> {
            let handle = unsafe { IcmpCreateFile() };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return None;
            }
            Some(Self { handle })
        }

        pub fn ping(&self, target: Ipv4Addr, ttl: u8, timeout: Duration) -> Reply {
            let options = IP_OPTION_INFORMATION {
                Ttl: ttl,
                Tos: 0,
                Flags: 0,
                OptionsSize: 0,
                OptionsData: std::ptr::null_mut(),
            };

            // Буфер должен вместить структуру ответа, наши данные и ещё
            // немного служебной информации. Выравнивание по 8 байт получаем
            // через u64: структура содержит указатели.
            let words = (size_of::<ICMP_ECHO_REPLY>() + PAYLOAD.len() + 64) / 8 + 1;
            let mut buffer = vec![0u64; words];
            let buffer_bytes = (buffer.len() * 8) as u32;

            let count = unsafe {
                IcmpSendEcho(
                    self.handle,
                    u32::from_ne_bytes(target.octets()),
                    PAYLOAD.as_ptr().cast(),
                    PAYLOAD.len() as u16,
                    &options,
                    buffer.as_mut_ptr().cast(),
                    buffer_bytes,
                    timeout.as_millis().min(u32::MAX as u128) as u32,
                )
            };

            if count == 0 {
                // Ответа в буфере нет, судить можно только по коду ошибки.
                let code = unsafe { GetLastError() };
                return match code {
                    IP_REQ_TIMED_OUT => Reply::timeout(),
                    IP_TTL_EXPIRED_TRANSIT => Reply {
                        kind: ReplyKind::TtlExpired,
                        from: None,
                        rtt: None,
                        detail: None,
                    },
                    other => Reply::error(format!("IcmpSendEcho: код {other}")),
                };
            }

            let reply = unsafe { &*buffer.as_ptr().cast::<ICMP_ECHO_REPLY>() };
            let from = IpAddr::V4(Ipv4Addr::from(reply.Address.to_ne_bytes()));
            let rtt = Duration::from_millis(reply.RoundTripTime as u64);

            let kind = match reply.Status {
                IP_SUCCESS => ReplyKind::Echo,
                IP_TTL_EXPIRED_TRANSIT => ReplyKind::TtlExpired,
                IP_DEST_NET_UNREACHABLE
                | IP_DEST_HOST_UNREACHABLE
                | IP_DEST_PROT_UNREACHABLE
                | IP_DEST_PORT_UNREACHABLE
                | IP_BAD_ROUTE => ReplyKind::Unreachable,
                IP_PACKET_TOO_BIG => ReplyKind::TooBig,
                IP_REQ_TIMED_OUT => return Reply::timeout(),
                other => {
                    return Reply {
                        kind: ReplyKind::Unreachable,
                        from: Some(from),
                        rtt: None,
                        detail: Some(format!("код состояния {other}")),
                    }
                }
            };

            Reply {
                kind,
                from: Some(from),
                // Ноль в поле RTT означает «меньше миллисекунды», а не «мгновенно»:
                // разрешение таймера здесь именно такое.
                rtt: Some(rtt),
                detail: None,
            }
        }
    }

    impl Drop for Inner {
        fn drop(&mut self) {
            unsafe { IcmpCloseHandle(self.handle) };
        }
    }
}

// ---------------------------------------------------------------------------
// Unix
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
mod backend {
    use super::{Reply, ReplyKind, PAYLOAD};
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::{Duration, Instant};

    use crate::privileged::IcmpBackend;

    pub struct Inner {
        socket: Socket,
    }

    impl Inner {
        pub fn new(backend: IcmpBackend) -> Option<Self> {
            let kind = match backend {
                IcmpBackend::RawSocket => Type::RAW,
                IcmpBackend::LinuxDgram => Type::DGRAM,
                // На Unix прочие варианты означают, что ICMP нам не дали.
                _ => return None,
            };
            let socket = Socket::new(Domain::IPV4, kind, Some(Protocol::ICMPV4)).ok()?;
            Some(Self { socket })
        }

        pub fn ping(&self, target: Ipv4Addr, ttl: u8, timeout: Duration) -> Reply {
            if self.socket.set_ttl_v4(ttl as u32).is_err() {
                return Reply::error("не удалось задать TTL");
            }
            if self.socket.set_read_timeout(Some(timeout)).is_err() {
                return Reply::error("не удалось задать тайм-аут чтения");
            }

            let id = std::process::id() as u16;
            let packet = echo_request(id, ttl as u16);
            let dest = SocketAddr::V4(SocketAddrV4::new(target, 0));

            let started = Instant::now();
            if let Err(e) = self.socket.send_to(&packet, &dest.into()) {
                return Reply::error(format!("отправка не удалась: {e}"));
            }

            // Сокет выделен под одну пробу за раз, поэтому первый пришедший
            // ICMP-ответ и есть ответ на неё.
            let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1500];
            let (len, addr) = match self.socket.recv_from(&mut buf) {
                Ok(v) => v,
                Err(_) => return Reply::timeout(),
            };
            let rtt = started.elapsed();
            let bytes: Vec<u8> = buf[..len]
                .iter()
                .map(|b| unsafe { b.assume_init() })
                .collect();

            let from = addr
                .as_socket_ipv4()
                .map(|a| IpAddr::V4(*a.ip()))
                .unwrap_or(IpAddr::V4(target));

            let Some(icmp) = strip_ip_header(&bytes) else {
                return Reply::error("слишком короткий ответ");
            };

            let kind = match icmp[0] {
                0 => ReplyKind::Echo,
                11 => ReplyKind::TtlExpired,
                // Код 13 в сообщении о недостижимости означает именно
                // административный запрет — это важный отдельный случай.
                3 if icmp.get(1) == Some(&13) => ReplyKind::Prohibited,
                3 if icmp.get(1) == Some(&4) => ReplyKind::TooBig,
                3 => ReplyKind::Unreachable,
                other => {
                    return Reply {
                        kind: ReplyKind::Unreachable,
                        from: Some(from),
                        rtt: Some(rtt),
                        detail: Some(format!("тип ICMP {other}")),
                    }
                }
            };

            Reply {
                kind,
                from: Some(from),
                rtt: Some(rtt),
                detail: None,
            }
        }
    }

    /// Raw-сокет отдаёт пакет вместе с IP-заголовком, датаграммный — без него.
    /// Определяем по версии в первом полубайте.
    fn strip_ip_header(bytes: &[u8]) -> Option<&[u8]> {
        if bytes.len() < 8 {
            return None;
        }
        if bytes[0] >> 4 == 4 {
            let header_len = (bytes[0] & 0x0F) as usize * 4;
            if bytes.len() <= header_len {
                return None;
            }
            return Some(&bytes[header_len..]);
        }
        Some(bytes)
    }

    fn echo_request(id: u16, seq: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(8 + PAYLOAD.len());
        packet.push(8); // тип: echo request
        packet.push(0); // код
        packet.extend_from_slice(&[0, 0]); // место под контрольную сумму
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&seq.to_be_bytes());
        packet.extend_from_slice(&PAYLOAD);

        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    /// Стандартная контрольная сумма интернета: сумма 16-битных слов
    /// с переносом, затем инверсия.
    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        if let Some(&last) = chunks.remainder().first() {
            sum += (last as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn checksum_of_packet_with_its_own_sum_is_zero() {
            // Свойство контрольной суммы: если посчитать её по пакету,
            // в котором она уже проставлена, получится ноль.
            let packet = echo_request(0x1234, 1);
            assert_eq!(checksum(&packet), 0);
        }

        #[test]
        fn ip_header_is_stripped_only_when_present() {
            let mut with_header = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            with_header.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
            assert_eq!(strip_ip_header(&with_header).unwrap().len(), 8);

            let bare = vec![0u8, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(strip_ip_header(&bare).unwrap().len(), 8);
        }
    }
}

use backend::Inner;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_kinds_are_classified() {
        assert!(ReplyKind::TtlExpired.got_response());
        assert!(!ReplyKind::Timeout.got_response());
        assert!(!ReplyKind::Error.got_response());
    }

    /// Локальная петля отвечает всегда и мгновенно — на ней проверяем,
    /// что транспорт вообще жив, не завися от наличия интернета.
    #[test]
    fn loopback_answers_when_icmp_is_available() {
        let caps = Capabilities::detect();
        let Some(pinger) = Pinger::new(caps) else {
            // ICMP недоступен в этом окружении — проверять нечего.
            return;
        };
        let reply = pinger.ping(Ipv4Addr::LOCALHOST, 64, Duration::from_secs(2));
        assert_eq!(reply.kind, ReplyKind::Echo, "ответ: {reply:?}");
    }
}
