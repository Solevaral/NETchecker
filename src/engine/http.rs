//! Проверка незащищённого HTTP: не подставляют ли вместо сайта заглушку.
//!
//! По обычному HTTP имя сайта передаётся открытым текстом в заголовке `Host`,
//! поэтому промежуточному оборудованию ничего не стоит ответить вместо сервера
//! своей страницей «доступ ограничен». Для человека это выглядит как ответ
//! сайта — в адресной строке тот же адрес.
//!
//! Отличаем это не по списку известных провайдеров (он бы устарел за месяц),
//! а по признакам самой подмены: ответ пришёл раньше, чем мог бы ответить
//! сервер; тот же сервер с другим `Host` ведёт себя иначе; в ответе есть
//! слова, которых на запрошенном сайте быть не может.
//!
//! Запрос отправляется вручную, а не готовым клиентом: нужен контроль над
//! заголовком `Host` при обращении по адресу, и нужен сырой ответ целиком.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// Ответ по HTTP.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    /// Куда предлагают перейти, если это перенаправление.
    pub location: Option<String>,
    /// Начало тела: заглушки короткие, а больше нам и не нужно.
    pub body: String,
    pub elapsed: Duration,
}

impl Response {
    pub fn describe(&self) -> String {
        let redirect = self
            .location
            .as_ref()
            .map(|l| format!(", перенаправление на {l}"))
            .unwrap_or_default();
        format!(
            "код {}{redirect}, ответ за {} мс",
            self.status,
            self.elapsed.as_millis()
        )
    }
}

/// Слова, которые встречаются на страницах-заглушках и почти не встречаются
/// на настоящих сайтах.
///
/// Это не список провайдеров и не реестр: провайдеров сотни, и перечислять
/// их бессмысленно. Ищем формулировки, которыми заглушка объясняет себя.
const STUB_MARKERS: [&str; 12] = [
    "доступ ограничен",
    "доступ к запрашиваемому ресурсу",
    "ограничение доступа",
    "ресурс заблокирован",
    "сайт заблокирован",
    "единый реестр",
    "реестр запрещённой информации",
    "роскомнадзор",
    "eais.rkn.gov.ru",
    "zapret-info",
    "blocked by",
    "access denied by",
];

/// Запрос к адресу с заданным именем сайта в заголовке.
pub fn get(address: Ipv4Addr, host: &str, timeout: Duration) -> Result<Response, String> {
    let addr = SocketAddr::new(address.into(), 80);
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("соединение: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;

    // Соединение закрываем сразу: держать его открытым незачем, а без
    // явного указания сервер будет ждать следующего запроса.
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: netchecker\r\n\
         Accept: text/html\r\nConnection: close\r\n\r\n"
    );

    let started = Instant::now();
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| format!("отправка: {e}"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                // Заглушки помещаются в несколько килобайт, а качать целиком
                // настоящий сайт нам незачем.
                if raw.len() > 16 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let elapsed = started.elapsed();

    if raw.is_empty() {
        return Err("ответа нет".into());
    }
    Ok(parse(&raw, elapsed))
}

fn parse(raw: &[u8], elapsed: Duration) -> Response {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_ref(), ""));

    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);

    let location = head
        .lines()
        .find(|l| l.to_lowercase().starts_with("location:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, value)| value.trim().to_string());

    Response {
        status,
        location,
        body: body.chars().take(4096).collect(),
        elapsed,
    }
}

/// Похож ли ответ на страницу-заглушку.
pub fn looks_like_stub(response: &Response, host: &str) -> Option<String> {
    let haystack = format!("{} {}", response.body, response.location.clone().unwrap_or_default())
        .to_lowercase();

    if let Some(marker) = STUB_MARKERS.iter().find(|m| haystack.contains(*m)) {
        return Some(format!("в ответе есть слова «{marker}»"));
    }

    // Перенаправление на чужой домен — второй характерный признак: настоящий
    // сайт уводит на себя же или на свой поддомен, а заглушка — на страницу
    // провайдера.
    if let Some(location) = &response.location {
        if let Some(target) = host_of(location) {
            if !related(&target, host) {
                return Some(format!("перенаправление на чужой домен {target}"));
            }
        }
    }

    None
}

/// Домен из ссылки.
fn host_of(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .strip_prefix("http://")
        .or_else(|| url.trim().strip_prefix("https://"))?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.rsplit('@').next()?;
    let host = host.split(':').next()?;
    (!host.is_empty()).then(|| host.to_lowercase())
}

/// Считаем домены родственными, если у них общие две последние части:
/// перенаправление с `example.com` на `www.example.com` — обычное дело.
fn related(a: &str, b: &str) -> bool {
    fn root(host: &str) -> String {
        let parts: Vec<&str> = host.trim_end_matches('.').rsplit('.').take(2).collect();
        parts.join(".")
    }
    root(a) == root(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: u16, body: &str, location: Option<&str>) -> Response {
        Response {
            status,
            location: location.map(str::to_string),
            body: body.to_string(),
            elapsed: Duration::from_millis(30),
        }
    }

    #[test]
    fn status_and_headers_are_parsed() {
        let raw = b"HTTP/1.1 302 Found\r\nLocation: http://block.isp.ru/\r\n\r\n<html>";
        let parsed = parse(raw, Duration::from_millis(10));
        assert_eq!(parsed.status, 302);
        assert_eq!(parsed.location.as_deref(), Some("http://block.isp.ru/"));
    }

    #[test]
    fn stub_wording_is_recognised() {
        let stub = response(200, "<h1>Доступ ограничен по решению суда</h1>", None);
        assert!(looks_like_stub(&stub, "example.com").is_some());
    }

    /// Перенаправление на собственный поддомен — обычная жизнь сайта,
    /// а не подмена.
    #[test]
    fn redirect_to_own_domain_is_not_a_stub() {
        let redirect = response(301, "", Some("https://www.example.com/"));
        assert!(looks_like_stub(&redirect, "example.com").is_none());
    }

    #[test]
    fn redirect_to_a_foreign_domain_is_suspicious() {
        let redirect = response(302, "", Some("http://blocked.provider.ru/notice"));
        assert!(looks_like_stub(&redirect, "example.com").is_some());
    }

    #[test]
    fn ordinary_page_is_left_alone() {
        let page = response(200, "<html><body>Пример страницы</body></html>", None);
        assert!(looks_like_stub(&page, "example.com").is_none());
    }

    #[test]
    fn host_is_extracted_from_url() {
        assert_eq!(host_of("http://a.b.ru:8080/x?y=1").as_deref(), Some("a.b.ru"));
        assert_eq!(host_of("не ссылка"), None);
    }
}
