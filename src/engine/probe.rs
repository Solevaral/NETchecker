//! Низкоуровневые пробы, на которых строятся проверки уровней L3–L4.
//!
//! Пока это TCP-пробы: они работают без каких-либо прав и уже позволяют
//! отличить «пакеты не уходят» от «сервер отказал». Точный ICMP появится
//! рядом и будет использоваться, когда его разрешает окружение.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Чем закончилась попытка установить TCP-соединение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpOutcome {
    /// Соединение установлено.
    Open { rtt: Duration },
    /// Пришёл явный отказ (RST) — узел на связи, но порт закрыт или сброшен.
    Refused { rtt: Duration },
    /// Ответа не было вовсе. Самый частый признак фильтрации по пути.
    Timeout,
    /// Локальная ошибка: нет маршрута, сеть недоступна.
    Unreachable { error: String },
}

impl TcpOutcome {
    pub fn is_open(&self) -> bool {
        matches!(self, TcpOutcome::Open { .. })
    }

    /// Короткое пояснение для строки доказательств.
    pub fn describe(&self) -> String {
        match self {
            TcpOutcome::Open { rtt } => format!("соединение установлено за {} мс", ms(*rtt)),
            TcpOutcome::Refused { rtt } => {
                format!("узел ответил отказом за {} мс", ms(*rtt))
            }
            TcpOutcome::Timeout => "ответа нет, тайм-аут".to_string(),
            TcpOutcome::Unreachable { error } => format!("сеть недоступна: {error}"),
        }
    }
}

pub fn ms(d: Duration) -> u128 {
    d.as_millis()
}

/// Попытка подключиться к адресу с ограничением по времени.
///
/// Различение отказа и тайм-аута здесь принципиально: явный RST означает, что
/// пакеты доходят и кто-то на них отвечает, а тишина — что их просто съели.
pub fn tcp_connect(addr: SocketAddr, timeout: Duration) -> TcpOutcome {
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout) {
        Ok(_) => TcpOutcome::Open {
            rtt: started.elapsed(),
        },
        Err(e) => match e.kind() {
            io::ErrorKind::TimedOut => TcpOutcome::Timeout,
            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
                TcpOutcome::Refused {
                    rtt: started.elapsed(),
                }
            }
            _ => TcpOutcome::Unreachable {
                error: e.to_string(),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcomes_describe_themselves() {
        assert!(TcpOutcome::Timeout.describe().contains("тайм-аут"));
        assert!(TcpOutcome::Open {
            rtt: Duration::from_millis(12)
        }
        .is_open());
    }

    /// Порт на localhost, который заведомо никто не слушает, обязан дать
    /// именно отказ, а не тайм-аут — на различении этих двух случаев держится
    /// вся логика «фильтруют» против «сервер отказал».
    ///
    /// Запас по времени щедрый намеренно: на машинах с антивирусом отказ по
    /// петлевому интерфейсу приходит через пару секунд, и короткий тайм-аут
    /// превратил бы тест в ложное срабатывание.
    #[test]
    fn closed_local_port_is_refused_not_timeout() {
        let addr: SocketAddr = "127.0.0.1:45789".parse().unwrap();
        let outcome = tcp_connect(addr, Duration::from_secs(5));
        assert!(
            matches!(outcome, TcpOutcome::Refused { .. }),
            "неожиданный результат: {outcome:?}"
        );
    }
}
