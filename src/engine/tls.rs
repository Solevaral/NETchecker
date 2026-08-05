//! Пробы по имени сайта внутри TLS.
//!
//! Современные блокировки редко работают по адресу — чаще фильтр читает имя
//! сайта из первого пакета TLS-рукопожатия (поле SNI) и обрывает соединение,
//! если имя в списке. Внешне это неотличимо от «сайт не работает»: соединение
//! просто закрывается.
//!
//! Отличить одно от другого можно только сравнением. Мы идём на **тот же
//! самый адрес** несколько раз, меняя ровно одну вещь, и смотрим на разницу:
//!
//! * с настоящим именем — обрыв, с нейтральным — сервер отвечает: значит дело
//!   в имени, а не в сервере;
//! * обрыв приходит быстрее, чем физически мог бы ответить сам сервер: значит
//!   отвечал не он, а оборудование по дороге.
//!
//! Рукопожатие собирается вручную. Готовая библиотека TLS здесь не подходит:
//! она сама решает, что и как отправить, а нам нужно контролировать
//! содержимое первого пакета и момент его отправки до байта.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Чем закончилась попытка начать рукопожатие.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// Сервер ответил своей частью рукопожатия — всё в порядке.
    ServerHello { rtt: Duration },
    /// Сервер вежливо отказался: прислал предупреждение TLS. Так отвечает,
    /// например, сервер, которому не понравилось имя, — но отвечает *он*.
    Alert { rtt: Duration, code: u8 },
    /// Соединение сброшено. Главный признак вмешательства.
    Reset { after: Duration },
    /// Закрыто без ответа и без сброса.
    Closed { after: Duration },
    /// Тишина до истечения времени.
    Timeout,
    /// Не удалось даже установить соединение.
    ConnectFailed { error: String },
}

impl Outcome {
    pub fn is_answered(&self) -> bool {
        matches!(self, Outcome::ServerHello { .. } | Outcome::Alert { .. })
    }

    /// Оборвано ли соединение — сбросом, закрытием или тишиной.
    pub fn is_broken(&self) -> bool {
        matches!(
            self,
            Outcome::Reset { .. } | Outcome::Closed { .. } | Outcome::Timeout
        )
    }

    /// Через сколько пришла реакция, если она вообще была.
    pub fn latency(&self) -> Option<Duration> {
        match self {
            Outcome::ServerHello { rtt } | Outcome::Alert { rtt, .. } => Some(*rtt),
            Outcome::Reset { after } | Outcome::Closed { after } => Some(*after),
            _ => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Outcome::ServerHello { rtt } => {
                format!("сервер ответил за {} мс", rtt.as_millis())
            }
            Outcome::Alert { rtt, code } => {
                format!("сервер отклонил соединение за {} мс (код {code})", rtt.as_millis())
            }
            Outcome::Reset { after } => {
                format!("соединение сброшено через {} мс", after.as_millis())
            }
            Outcome::Closed { after } => {
                format!("соединение закрыто без ответа через {} мс", after.as_millis())
            }
            Outcome::Timeout => "ответа нет".to_string(),
            Outcome::ConnectFailed { error } => format!("не удалось соединиться: {error}"),
        }
    }
}

/// Как отправлять рукопожатие.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// Одним куском — как это делает обычный браузер.
    Whole,
    /// Двумя частями с паузой.
    ///
    /// Разница в поведении между целым и разделённым пакетом — прямое
    /// доказательство, что имя сайта читает промежуточное оборудование:
    /// настоящему серверу всё равно, сколькими кусками пришли данные,
    /// он собирает поток обратно.
    Split,
}

/// Одна проба: соединиться и начать рукопожатие с заданным именем.
pub fn probe(
    address: Ipv4Addr,
    port: u16,
    sni: &str,
    delivery: Delivery,
    timeout: Duration,
) -> Outcome {
    let addr = SocketAddr::new(address.into(), port);
    let mut stream = match TcpStream::connect_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            return Outcome::ConnectFailed {
                error: e.to_string(),
            }
        }
    };

    if stream.set_read_timeout(Some(timeout)).is_err() || stream.set_nodelay(true).is_err() {
        return Outcome::ConnectFailed {
            error: "не удалось настроить сокет".into(),
        };
    }

    let hello = client_hello(sni);
    let started = Instant::now();

    let sent = match delivery {
        Delivery::Whole => stream.write_all(&hello),
        Delivery::Split => {
            // Режем так, чтобы имя сайта не оказалось целиком в первом куске.
            let cut = (hello.len() / 2).max(1);
            stream
                .write_all(&hello[..cut])
                .and_then(|_| stream.flush())
                .and_then(|_| {
                    std::thread::sleep(Duration::from_millis(30));
                    stream.write_all(&hello[cut..])
                })
        }
    };

    if let Err(e) = sent.and_then(|_| stream.flush()) {
        return classify_error(&e, started.elapsed());
    }

    let mut buf = [0u8; 1024];
    match stream.read(&mut buf) {
        Ok(0) => Outcome::Closed {
            after: started.elapsed(),
        },
        Ok(n) => classify_response(&buf[..n], started.elapsed()),
        Err(e) => classify_error(&e, started.elapsed()),
    }
}

fn classify_error(error: &std::io::Error, after: Duration) -> Outcome {
    match error.kind() {
        std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
            Outcome::Reset { after }
        }
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Outcome::Timeout,
        _ => Outcome::Closed { after },
    }
}

/// Первый байт записи TLS говорит, что это: 0x16 — рукопожатие,
/// 0x15 — предупреждение.
fn classify_response(bytes: &[u8], rtt: Duration) -> Outcome {
    match bytes.first() {
        Some(0x16) => Outcome::ServerHello { rtt },
        Some(0x15) => Outcome::Alert {
            rtt,
            // В записи предупреждения интересен второй байт содержимого — код.
            code: bytes.get(6).copied().unwrap_or(0),
        },
        _ => Outcome::Closed { after: rtt },
    }
}

/// Собирает ClientHello с указанным именем сайта.
fn client_hello(sni: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(256);

    body.extend_from_slice(&[0x03, 0x03]); // версия TLS 1.2
    body.extend_from_slice(&client_random());
    body.push(0); // без идентификатора сессии

    let suites: [u16; 9] = [
        0x1301, 0x1302, 0x1303, // TLS 1.3
        0xC02B, 0xC02F, 0xC02C, 0xC030, // ECDHE
        0x009C, 0x009D, // запасные
    ];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }

    body.extend_from_slice(&[1, 0]); // способы сжатия: только «без сжатия»

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&extension_sni(sni));
    extensions.extend_from_slice(&extension(0x000A, &[0x00, 0x04, 0x00, 0x1D, 0x00, 0x17])); // группы
    extensions.extend_from_slice(&extension(0x000B, &[0x01, 0x00])); // формат точек
    extensions.extend_from_slice(&extension(
        0x000D,
        &[0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x02, 0x01],
    )); // алгоритмы подписи
    extensions.extend_from_slice(&extension(0x002B, &[0x04, 0x03, 0x04, 0x03, 0x03])); // версии
    extensions.extend_from_slice(&extension(0x002D, &[0x01, 0x01])); // режимы обмена ключами
    extensions.extend_from_slice(&extension_key_share());

    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    // Заголовок рукопожатия: тип и длина в три байта.
    let mut handshake = Vec::with_capacity(body.len() + 4);
    handshake.push(0x01);
    let len = body.len();
    handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    handshake.extend_from_slice(&body);

    // Запись TLS.
    let mut record = Vec::with_capacity(handshake.len() + 5);
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn extension(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Заготовка ключа для TLS 1.3.
///
/// Без неё сервер, согласившийся на TLS 1.3, отвечает отказом
/// «отсутствует расширение» — и проба провалилась бы на любом сайте,
/// вообще не дойдя до проверки имени.
///
/// Настоящий ключ не нужен: до обмена секретами дело не доходит, нас
/// интересует только сам факт ответа сервера.
fn extension_key_share() -> Vec<u8> {
    let key = client_random(); // 32 байта — ровно размер ключа x25519
    let mut payload = Vec::with_capacity(key.len() + 6);
    payload.extend_from_slice(&((key.len() + 4) as u16).to_be_bytes()); // длина списка
    payload.extend_from_slice(&0x001Du16.to_be_bytes()); // группа x25519
    payload.extend_from_slice(&(key.len() as u16).to_be_bytes());
    payload.extend_from_slice(&key);
    extension(0x0033, &payload)
}

fn extension_sni(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut payload = Vec::with_capacity(name.len() + 5);
    payload.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // длина списка
    payload.push(0); // тип: имя узла
    payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
    payload.extend_from_slice(name);
    extension(0x0000, &payload)
}

/// Случайные байты рукопожатия.
///
/// Криптостойкость здесь не нужна: до обмена ключами дело не доходит, нам
/// важно лишь, чтобы пробы не выглядели одинаковыми копиями друг друга.
fn client_random() -> [u8; 32] {
    use std::hash::{BuildHasher as _, RandomState};

    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        let value = RandomState::new().hash_one(Instant::now().elapsed().as_nanos() as u64);
        let bytes = value.to_ne_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Проба обязана содержать заготовку ключа: без неё сервер, согласившийся
    /// на TLS 1.3, отвечает отказом «отсутствует расширение», и любой сайт
    /// выглядел бы сломанным.
    #[test]
    fn hello_offers_a_key_share_for_tls13() {
        let hello = client_hello("example.com");
        let key_share = [0x00u8, 0x33];
        assert!(
            hello.windows(2).any(|w| w == key_share),
            "в ClientHello нет расширения key_share"
        );
    }

    #[test]
    fn hello_is_a_well_formed_tls_record() {
        let hello = client_hello("example.com");
        assert_eq!(hello[0], 0x16, "запись должна быть рукопожатием");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(record_len, hello.len() - 5, "длина записи должна сходиться");

        let handshake_len =
            ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(handshake_len, hello.len() - 9, "длина рукопожатия должна сходиться");
    }

    /// Имя сайта обязано попасть в пакет как есть: на нём держится вся проба.
    #[test]
    fn hello_carries_the_requested_name() {
        let hello = client_hello("rutracker.org");
        let needle = b"rutracker.org";
        assert!(
            hello.windows(needle.len()).any(|w| w == needle),
            "имя сайта не попало в ClientHello"
        );
    }

    #[test]
    fn different_names_give_different_packets() {
        let a = client_hello("a.example");
        let b = client_hello("bb.example");
        assert_ne!(a, b);
    }

    #[test]
    fn outcomes_are_classified() {
        assert!(Outcome::ServerHello {
            rtt: Duration::from_millis(10)
        }
        .is_answered());
        assert!(Outcome::Reset {
            after: Duration::from_millis(2)
        }
        .is_broken());
        assert!(Outcome::Timeout.is_broken());
        assert!(!Outcome::Timeout.is_answered());
    }

    #[test]
    fn tls_alert_record_is_recognised() {
        let bytes = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
        let outcome = classify_response(&bytes, Duration::from_millis(5));
        assert_eq!(
            outcome,
            Outcome::Alert {
                rtt: Duration::from_millis(5),
                code: 0x28
            }
        );
    }
}
