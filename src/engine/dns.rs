//! Работа с DNS: собственный разбор пакетов, запросы по UDP и по HTTPS.
//!
//! Стандартный резолвер системы здесь не годится принципиально. Нам нужно не
//! «узнать адрес», а *сравнить*, что отвечают разные источники: системный
//! резолвер, публичные серверы напрямую и зашифрованный DoH. Расхождение между
//! ними и есть подмена. Системный API такого сравнения не позволяет — он
//! возвращает готовый ответ, скрывая, кто и что на самом деле сказал.
//!
//! Пакеты собираются и разбираются вручную. DNS-сообщение простое, а своя
//! реализация даёт то, ради чего всё затевалось: доступ к коду ответа, к TTL
//! и к сырым байтам.

use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Тип запрашиваемой записи: адрес IPv4.
const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

/// Ответ на один запрос.
#[derive(Debug, Clone)]
pub struct Answer {
    pub addresses: Vec<Ipv4Addr>,
    /// Код ответа из заголовка: 0 — успех, 3 — имени не существует.
    pub rcode: u8,
    /// Наименьший TTL среди записей. Подозрительно круглые или очень маленькие
    /// значения — один из признаков подделанного ответа.
    pub min_ttl: Option<u32>,
    pub elapsed: Duration,
}

impl Answer {
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Ответ, который формально успешен, но ведёт в никуда: так выглядят
    /// заглушки провайдеров.
    pub fn is_blackhole(&self) -> bool {
        !self.addresses.is_empty()
            && self
                .addresses
                .iter()
                .all(|a| a.is_unspecified() || a.is_loopback())
    }

    pub fn describe(&self) -> String {
        if self.addresses.is_empty() {
            return format!("код ответа {} ({}), адресов нет", self.rcode, rcode_name(self.rcode));
        }
        let list: Vec<String> = self.addresses.iter().map(|a| a.to_string()).collect();
        let ttl = self
            .min_ttl
            .map(|t| format!(", TTL {t} с"))
            .unwrap_or_default();
        format!("{}{ttl}, за {} мс", list.join(", "), self.elapsed.as_millis())
    }
}

pub fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "успех",
        1 => "ошибка формата запроса",
        2 => "сбой сервера",
        3 => "имя не существует",
        4 => "запрос не поддерживается",
        5 => "отказано",
        _ => "неизвестный код",
    }
}

/// Запрос по UDP к конкретному серверу.
///
/// Именно «к конкретному»: смысл всей проверки в том, чтобы спросить каждый
/// сервер отдельно и сравнить, а не отдать выбор системе.
pub fn query_udp(server: IpAddr, name: &str, timeout: Duration) -> Result<Answer, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("не удалось открыть сокет: {e}"))?;
    socket
        .set_read_timeout(Some(timeout))
        .map_err(|e| format!("не удалось задать тайм-аут: {e}"))?;

    let id = (std::process::id() ^ name.len() as u32) as u16;
    let query = encode_query(id, name)?;

    let started = Instant::now();
    socket
        .send_to(&query, SocketAddr::new(server, 53))
        .map_err(|e| format!("отправка не удалась: {e}"))?;

    let mut buf = [0u8; 1500];
    let (len, _) = socket
        .recv_from(&mut buf)
        .map_err(|_| "ответа нет".to_string())?;

    let mut answer = decode_answer(&buf[..len])?;
    answer.elapsed = started.elapsed();
    Ok(answer)
}

/// Запрос по DoH — DNS внутри HTTPS.
///
/// Провайдер видит только зашифрованное соединение и подменить ответ не может,
/// поэтому DoH служит эталоном, с которым сравнивается всё остальное.
///
/// Адрес сервера намеренно задаётся числом, а не именем: если DNS сломан или
/// подменён, разрешать имя самого DoH-сервера было бы замкнутым кругом.
pub fn query_doh(agent: &ureq::Agent, url: &str, name: &str) -> Result<Answer, String> {
    let id = 0; // По RFC 8484 идентификатор в DoH принято обнулять.
    let query = encode_query(id, name)?;

    let started = Instant::now();
    let mut response = agent
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .send(&query[..])
        .map_err(|e| format!("запрос не прошёл: {e}"))?;

    let mut body = Vec::new();
    response
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .map_err(|e| format!("не удалось прочитать ответ: {e}"))?;

    let mut answer = decode_answer(&body)?;
    answer.elapsed = started.elapsed();
    Ok(answer)
}

/// Собирает запрос в проволочный формат.
fn encode_query(id: u16, name: &str) -> Result<Vec<u8>, String> {
    let mut packet = Vec::with_capacity(32 + name.len());
    packet.extend_from_slice(&id.to_be_bytes());
    // Флаги: обычный запрос с рекурсией.
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // вопросов: 1
    packet.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ответов, авторитетных, дополнительных: 0

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("недопустимая часть имени: «{label}»"));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0); // конец имени

    packet.extend_from_slice(&TYPE_A.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(packet)
}

/// Разбирает ответ, вытаскивая адреса и код результата.
fn decode_answer(packet: &[u8]) -> Result<Answer, String> {
    if packet.len() < 12 {
        return Err("ответ короче заголовка".into());
    }

    let rcode = packet[3] & 0x0F;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    let ancount = u16::from_be_bytes([packet[6], packet[7]]);

    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(packet, pos)?;
        pos += 4; // тип и класс вопроса
    }

    let mut addresses = Vec::new();
    let mut min_ttl: Option<u32> = None;

    for _ in 0..ancount {
        pos = skip_name(packet, pos)?;
        if pos + 10 > packet.len() {
            break;
        }
        let rtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let ttl = u32::from_be_bytes([
            packet[pos + 4],
            packet[pos + 5],
            packet[pos + 6],
            packet[pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[pos + 8], packet[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlen > packet.len() {
            break;
        }
        if rtype == TYPE_A && rdlen == 4 {
            addresses.push(Ipv4Addr::new(
                packet[pos],
                packet[pos + 1],
                packet[pos + 2],
                packet[pos + 3],
            ));
            min_ttl = Some(min_ttl.map_or(ttl, |m: u32| m.min(ttl)));
        }
        pos += rdlen;
    }

    Ok(Answer {
        addresses,
        rcode,
        min_ttl,
        elapsed: Duration::ZERO,
    })
}

/// Пропускает имя, учитывая сжатие ссылками.
///
/// Указатель может вести куда угодно, в том числе сам на себя, поэтому
/// перепрыгиваем ровно один раз: имя после ссылки всё равно не продолжается.
fn skip_name(packet: &[u8], mut pos: usize) -> Result<usize, String> {
    loop {
        let Some(&len) = packet.get(pos) else {
            return Err("имя выходит за границы пакета".into());
        };
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Ссылка занимает два байта и завершает имя.
            return Ok(pos + 2);
        }
        pos += 1 + len as usize;
        if pos > packet.len() {
            return Err("имя выходит за границы пакета".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_is_encoded_in_wire_format() {
        let q = encode_query(0xABCD, "ya.ru").unwrap();
        assert_eq!(&q[0..2], &[0xAB, 0xCD]);
        assert_eq!(&q[4..6], &[0, 1], "должен быть ровно один вопрос");
        // 2 "ya" 2 "ru" 0
        assert_eq!(&q[12..], &[2, b'y', b'a', 2, b'r', b'u', 0, 0, 1, 0, 1]);
    }

    #[test]
    fn overlong_label_is_rejected() {
        let long = "a".repeat(64);
        assert!(encode_query(1, &long).is_err());
    }

    #[test]
    fn answer_with_one_address_is_decoded() {
        let mut packet = vec![
            0xAB, 0xCD, // id
            0x81, 0x80, // флаги, rcode 0
            0, 1, // вопросов
            0, 1, // ответов
            0, 0, 0, 0,
        ];
        packet.extend_from_slice(&[2, b'y', b'a', 2, b'r', b'u', 0]);
        packet.extend_from_slice(&[0, 1, 0, 1]); // тип и класс вопроса
        packet.extend_from_slice(&[0xC0, 0x0C]); // имя ссылкой
        packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        packet.extend_from_slice(&300u32.to_be_bytes());
        packet.extend_from_slice(&[0, 4]);
        packet.extend_from_slice(&[77, 88, 55, 242]);

        let answer = decode_answer(&packet).unwrap();
        assert_eq!(answer.addresses, vec![Ipv4Addr::new(77, 88, 55, 242)]);
        assert_eq!(answer.rcode, 0);
        assert_eq!(answer.min_ttl, Some(300));
    }

    /// Обрезанный или испорченный пакет не должен ронять программу:
    /// подделанные ответы попадаются именно кривыми.
    #[test]
    fn truncated_packet_does_not_panic() {
        let mut packet = vec![0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        packet.extend_from_slice(&[2, b'y', b'a']); // имя обрывается
        assert!(decode_answer(&packet).is_err() || decode_answer(&packet).unwrap().is_empty());
    }

    #[test]
    fn stub_answers_are_recognised() {
        let stub = Answer {
            addresses: vec![Ipv4Addr::UNSPECIFIED],
            rcode: 0,
            min_ttl: None,
            elapsed: Duration::ZERO,
        };
        assert!(stub.is_blackhole());

        let real = Answer {
            addresses: vec![Ipv4Addr::new(77, 88, 55, 242)],
            rcode: 0,
            min_ttl: None,
            elapsed: Duration::ZERO,
        };
        assert!(!real.is_blackhole());
    }
}
