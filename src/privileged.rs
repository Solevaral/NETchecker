//! Определение доступного ICMP-транспорта.
//!
//! Программа работает без прав администратора, но с правами делает более точные
//! замеры. Здесь мы один раз выясняем, что нам доступно, и дальше движок просто
//! смотрит на результат. Ни одна проверка не должна молча исчезать: то, что
//! недоступно, помечается как пропущенное с объяснением.

use socket2::{Domain, Protocol, Socket, Type};

/// Способ отправки ICMP-эхо, по убыванию точности.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpBackend {
    /// Raw-сокет: полный доступ к заголовкам и ICMP-ошибкам. Нужны права.
    RawSocket,
    /// `IcmpSendEcho2` из iphlpapi — на Windows работает без администратора.
    WindowsIcmpApi,
    /// `SOCK_DGRAM`+`IPPROTO_ICMP` — на Linux работает без root,
    /// если разрешает `net.ipv4.ping_group_range`.
    LinuxDgram,
    /// Ничего из перечисленного: остаются TCP-пробы и системные утилиты.
    Fallback,
}

impl IcmpBackend {
    pub fn title(self) -> &'static str {
        match self {
            IcmpBackend::RawSocket => "Расширенный режим",
            IcmpBackend::WindowsIcmpApi => "Обычный режим",
            IcmpBackend::LinuxDgram => "Обычный режим",
            IcmpBackend::Fallback => "Ограниченный режим",
        }
    }

    /// Что это значит для пользователя.
    pub fn explanation(self) -> &'static str {
        match self {
            IcmpBackend::RawSocket => {
                "Доступны точные замеры задержек и разбор сетевых ошибок по пути."
            }
            IcmpBackend::WindowsIcmpApi => {
                "Доступны ping и трассировка. Для самых точных замеров запустите программу \
                 от имени администратора."
            }
            IcmpBackend::LinuxDgram => {
                "Доступны ping и трассировка. Для самых точных замеров запустите программу \
                 через sudo или выдайте ей CAP_NET_RAW."
            }
            IcmpBackend::Fallback => {
                "ICMP недоступен: система не даёт отправлять эхо-запросы. Проверки пойдут \
                 через TCP-пробы, трассировка будет менее подробной."
            }
        }
    }
}

/// Что программа может делать в текущем окружении.
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub icmp: IcmpBackend,
    /// Запущены ли мы с повышенными правами.
    pub elevated: bool,
}

impl Capabilities {
    /// Разовая проба окружения. Дешёвая: только открывает и сразу закрывает сокеты.
    pub fn detect() -> Self {
        let elevated = raw_icmp_available();

        let icmp = if elevated {
            IcmpBackend::RawSocket
        } else if cfg!(windows) {
            // IcmpSendEcho2 доступен любому процессу на Windows.
            IcmpBackend::WindowsIcmpApi
        } else if dgram_icmp_available() {
            IcmpBackend::LinuxDgram
        } else {
            IcmpBackend::Fallback
        };

        Self { icmp, elevated }
    }
}

/// Удаётся ли открыть raw-сокет для ICMP. На Windows это доступно только
/// администратору, на Linux — только root или процессу с CAP_NET_RAW,
/// поэтому проба заодно служит проверкой повышенных прав.
fn raw_icmp_available() -> bool {
    Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).is_ok()
}

/// Непривилегированный ICMP через датаграммный сокет (Linux).
fn dgram_icmp_available() -> bool {
    Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Проба не должна паниковать ни в каком окружении, включая CI без сети.
    #[test]
    fn detect_is_infallible() {
        let caps = Capabilities::detect();
        assert!(!caps.icmp.explanation().is_empty());
    }

    /// Без прав на Windows мы обязаны выбрать API-путь, а не уходить в заглушку.
    #[test]
    fn windows_without_rights_still_has_icmp() {
        let caps = Capabilities::detect();
        if cfg!(windows) && !caps.elevated {
            assert_eq!(caps.icmp, IcmpBackend::WindowsIcmpApi);
        }
    }
}
