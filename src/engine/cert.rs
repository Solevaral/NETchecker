//! Разбор сертификата сервера.
//!
//! Если между вами и сайтом стоит оборудование, вскрывающее защищённые
//! соединения, оно вынуждено предъявлять браузеру свой сертификат вместо
//! настоящего. Это и есть то, что мы ищем: не «плохой» сертификат вообще,
//! а сертификат, выданный **не на тот сайт**, к которому мы обращались,
//! либо выписанный сам себе.
//!
//! Проверять подпись удостоверяющим центром мы намеренно не беремся: для
//! этого нужен список доверенных корней и вся машинерия проверки цепочки,
//! а вывод она даёт тот же самый в интересующем нас случае. Несовпадение
//! имени — признак и более простой, и более наглядный для человека.
//!
//! Разбор идёт по сырому DER, потому что сертификат приходится доставать
//! из рукопожатия вручную: в TLS 1.3 он зашифрован, и проба ради него
//! ходит отдельно, в режиме TLS 1.2.

/// Что удалось прочитать в сертификате.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// Кому выдан — общее имя из поля subject.
    pub subject: Option<String>,
    /// Кем выдан — общее имя из поля issuer.
    pub issuer: Option<String>,
    /// Имена, на которые сертификат действителен (subjectAltName).
    pub names: Vec<String>,
}

impl Info {
    /// Выдан ли сертификат сам себе. Настоящие сайты такими не пользуются.
    pub fn self_signed(&self) -> bool {
        match (&self.subject, &self.issuer) {
            (Some(s), Some(i)) => s == i,
            _ => false,
        }
    }

    /// Годится ли сертификат для запрошенного имени.
    pub fn covers(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_lowercase();
        self.names
            .iter()
            .chain(self.subject.iter())
            .any(|name| matches_name(name, &domain))
    }

    pub fn describe(&self) -> String {
        let subject = self.subject.clone().unwrap_or_else(|| "не указано".into());
        let issuer = self.issuer.clone().unwrap_or_else(|| "не указан".into());
        let names = if self.names.is_empty() {
            String::new()
        } else {
            format!(", действителен для: {}", self.names.join(", "))
        };
        format!("выдан «{subject}», кем выдан: «{issuer}»{names}")
    }
}

/// Сверка имени из сертификата с запрошенным, с учётом звёздочки.
///
/// Звёздочка покрывает ровно один уровень имени: `*.example.com` годится
/// для `www.example.com`, но не для `a.b.example.com` и не для самого
/// `example.com`.
fn matches_name(pattern: &str, domain: &str) -> bool {
    let pattern = pattern.trim().trim_end_matches('.').to_lowercase();
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return pattern == domain;
    };
    match domain.split_once('.') {
        Some((_, rest)) => rest == suffix,
        None => false,
    }
}

/// Достаёт первый сертификат из сообщения Certificate рукопожатия.
pub fn from_handshake(messages: &[(u8, Vec<u8>)]) -> Option<Info> {
    let body = messages
        .iter()
        .find(|(kind, _)| *kind == 11)
        .map(|(_, body)| body)?;

    // Certificate: длина списка (3 байта), затем для каждого сертификата
    // его длина (3 байта) и содержимое.
    if body.len() < 6 {
        return None;
    }
    let first_len = ((body[3] as usize) << 16) | ((body[4] as usize) << 8) | body[5] as usize;
    let der = body.get(6..6 + first_len)?;
    parse(der)
}

/// Разбор сертификата в формате DER.
pub fn parse(der: &[u8]) -> Option<Info> {
    // Certificate ::= SEQUENCE { tbsCertificate, подпись, значение подписи }
    let (outer_tag, certificate) = tlv(der, 0)?;
    if outer_tag != 0x30 {
        return None;
    }
    let (tbs_tag, tbs) = tlv(der, certificate.start)?;
    if tbs_tag != 0x30 {
        return None;
    }

    // Дальше идём по полям tbsCertificate по порядку. Первое поле —
    // необязательный номер версии, помеченный контекстным тегом [0].
    let mut pos = tbs.start;
    let (tag, version) = tlv(der, pos)?;
    if tag == 0xA0 {
        pos = version.end;
    }

    let (_, serial) = tlv(der, pos)?; // serialNumber
    pos = serial.end;
    let (_, algorithm) = tlv(der, pos)?; // signature
    pos = algorithm.end;

    let (_, issuer) = tlv(der, pos)?; // issuer
    let issuer_cn = common_name(der, issuer.clone());
    pos = issuer.end;

    let (_, validity) = tlv(der, pos)?; // validity
    pos = validity.end;

    let (_, subject) = tlv(der, pos)?; // subject
    let subject_cn = common_name(der, subject.clone());

    Some(Info {
        subject: subject_cn,
        issuer: issuer_cn,
        names: alt_names(der),
    })
}

/// Диапазон байтов внутри среза.
type Range = std::ops::Range<usize>;

/// Читает один элемент DER: возвращает тег и границы содержимого.
fn tlv(der: &[u8], pos: usize) -> Option<(u8, Range)> {
    let tag = *der.get(pos)?;
    let first = *der.get(pos + 1)? as usize;

    let (len, header) = if first & 0x80 == 0 {
        (first, 2)
    } else {
        // Длинная форма: младшие биты — сколько дальше байтов длины.
        let count = first & 0x7F;
        if count == 0 || count > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | *der.get(pos + 2 + i)? as usize;
        }
        (len, 2 + count)
    };

    let start = pos + header;
    let end = start.checked_add(len)?;
    if end > der.len() {
        return None;
    }
    Some((tag, start..end))
}

/// Общее имя (CN) внутри поля Name.
fn common_name(der: &[u8], range: Range) -> Option<String> {
    // Name ::= SEQUENCE OF SET OF SEQUENCE { тип OID, значение }
    const OID_CN: [u8; 3] = [0x55, 0x04, 0x03];

    let mut pos = range.start;
    while pos < range.end {
        let (_, set) = tlv(der, pos)?;
        let mut inner = set.start;
        while inner < set.end {
            let (_, pair) = tlv(der, inner)?;
            let (oid_tag, oid) = tlv(der, pair.start)?;
            if oid_tag == 0x06 && der.get(oid.clone())? == OID_CN {
                let (_, value) = tlv(der, oid.end)?;
                return Some(String::from_utf8_lossy(der.get(value)?).into_owned());
            }
            inner = pair.end;
        }
        pos = set.end;
    }
    None
}

/// Имена из расширения subjectAltName.
///
/// Расширение ищется по своему идентификатору во всём теле сертификата:
/// путь до него длинный и необязательный, а идентификатор уникален.
fn alt_names(der: &[u8]) -> Vec<String> {
    const OID_SAN: [u8; 5] = [0x06, 0x03, 0x55, 0x1D, 0x11];

    let Some(start) = der.windows(OID_SAN.len()).position(|w| w == OID_SAN) else {
        return Vec::new();
    };

    // За идентификатором идёт необязательный признак критичности,
    // затем OCTET STRING с содержимым расширения.
    let mut pos = start + OID_SAN.len();
    if der.get(pos) == Some(&0x01) {
        let Some((_, critical)) = tlv(der, pos) else {
            return Vec::new();
        };
        pos = critical.end;
    }

    let Some((tag, octets)) = tlv(der, pos) else {
        return Vec::new();
    };
    if tag != 0x04 {
        return Vec::new();
    }
    let Some((_, list)) = tlv(der, octets.start) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    let mut item = list.start;
    while item < list.end {
        let Some((tag, value)) = tlv(der, item) else {
            break;
        };
        // Контекстный тег 2 — доменное имя.
        if tag == 0x82 {
            if let Some(bytes) = der.get(value.clone()) {
                names.push(String::from_utf8_lossy(bytes).into_owned());
            }
        }
        item = value.end;
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(subject: &str, issuer: &str, names: &[&str]) -> Info {
        Info {
            subject: Some(subject.into()),
            issuer: Some(issuer.into()),
            names: names.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn wildcard_covers_exactly_one_level() {
        assert!(matches_name("*.example.com", "www.example.com"));
        assert!(!matches_name("*.example.com", "a.b.example.com"));
        assert!(!matches_name("*.example.com", "example.com"));
        assert!(matches_name("example.com", "example.com"));
    }

    #[test]
    fn certificate_for_another_site_does_not_cover_ours() {
        let cert = info("provider-filter", "provider-filter", &["*.provider.ru"]);
        assert!(!cert.covers("discord.com"));
        assert!(cert.self_signed());
    }

    #[test]
    fn real_certificate_covers_its_names() {
        let cert = info("*.example.com", "Some CA", &["example.com", "*.example.com"]);
        assert!(cert.covers("example.com"));
        assert!(cert.covers("www.example.com"));
        assert!(!cert.self_signed());
    }

    #[test]
    fn trailing_dot_in_domain_is_ignored() {
        let cert = info("example.com", "CA", &["example.com"]);
        assert!(cert.covers("example.com."));
    }

    /// Разборщик встречает и обрезанные, и намеренно испорченные данные:
    /// подделанные ответы попадаются именно такими.
    #[test]
    fn broken_input_does_not_panic() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x30, 0x82, 0xFF]).is_none());
        assert!(parse(&[0x30, 0x03, 0x30, 0x01, 0x00]).is_none());
        assert!(from_handshake(&[(11, vec![0, 0, 3, 0, 0])]).is_none());
    }

    /// Разбор длины в длинной форме — самое частое место ошибок в DER.
    #[test]
    fn long_form_length_is_read_correctly() {
        // SEQUENCE длиной 300 байт: 0x82 означает «длина в двух байтах».
        let mut der = vec![0x30, 0x82, 0x01, 0x2C];
        der.extend(std::iter::repeat_n(0u8, 300));
        let (tag, range) = tlv(&der, 0).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(range.len(), 300);
    }
}
