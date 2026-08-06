//! Список проверяемых целей — доменов и адресов.
//!
//! Список принадлежит пользователю, а не программе. У каждого свои сайты,
//! которые «не открываются», и зашитый в код перечень отвечал бы на чужой
//! вопрос. Поэтому цели редактируются в окне, сохраняются между запусками
//! и задаются просто построчно: список удобнее всего вставлять целиком.

use std::net::Ipv4Addr;

/// Что именно проверяем.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// Имя сайта: можно проверить и подмену DNS, и фильтрацию по имени.
    Domain,
    /// Голый адрес: имени нет, поэтому проверяется только доступность.
    Address(Ipv4Addr),
}

impl Kind {
    pub fn title(&self) -> &'static str {
        match self {
            Kind::Domain => "домен",
            Kind::Address(_) => "адрес",
        }
    }
}

/// Одна цель.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Строка в том виде, в каком её увидит пользователь.
    pub value: String,
    pub kind: Kind,
}

impl Target {
    pub fn is_domain(&self) -> bool {
        self.kind == Kind::Domain
    }
}

/// Ресурсы, которые в России работают у всех.
///
/// Без них список бесполезен. «Сайт не открывается» само по себе не значит
/// ничего: так выглядит и блокировка, и оборванный кабель. Смысл появляется
/// только в сравнении — если эти открываются, а остальные нет, дело точно
/// не в подключении.
const CONTROLS: [&str; 5] = [
    "ya.ru",
    "vk.com",
    "gosuslugi.ru",
    "example.com",
    "cloudflare.com",
];

/// Ресурсы, с которыми у российских пользователей обычно бывают сложности:
/// блокировки, замедление, обрыв соединения по имени сайта.
///
/// Список заведомо неполный и устареет — он не реестр, а набор образцов для
/// сравнения. Пользователь правит его под себя на вкладке «Цели».
const USUALLY_BLOCKED: [&str; 13] = [
    "www.youtube.com",
    "discord.com",
    "instagram.com",
    "www.facebook.com",
    "x.com",
    "telegram.org",
    "chatgpt.com",
    "claude.ai",
    "www.linkedin.com",
    "medium.com",
    "signal.org",
    "soundcloud.com",
    "rutracker.org",
];

/// Сколько целей в списке по умолчанию: эталоны плюс проблемные.
#[cfg(test)]
const DEFAULTS_LEN: usize = CONTROLS.len() + USUALLY_BLOCKED.len();

/// Список по умолчанию одной строкой на цель.
pub fn defaults() -> Vec<String> {
    CONTROLS
        .iter()
        .chain(USUALLY_BLOCKED.iter())
        .map(|s| s.to_string())
        .collect()
}

/// Сколько целей разрешено. Ограничение не техническое, а по времени: каждая
/// цель — это несколько сетевых проб, и список на тысячу строк превратил бы
/// проверку в получасовое ожидание.
pub const MAX: usize = 40;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetList {
    items: Vec<Target>,
}

impl Default for TargetList {
    fn default() -> Self {
        Self::from_lines(&defaults()).0
    }
}

impl TargetList {
    pub fn items(&self) -> &[Target] {
        &self.items
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Разбирает текст из поля ввода: одна цель на строку.
    ///
    /// Возвращает список и строки, которые не удалось понять, — молча
    /// выбрасывать пользовательский ввод нельзя, человек должен увидеть,
    /// что именно программа не приняла.
    pub fn parse(text: &str) -> (Self, Vec<String>) {
        let lines: Vec<String> = text.lines().map(str::to_string).collect();
        Self::from_lines(&lines)
    }

    pub fn from_lines(lines: &[String]) -> (Self, Vec<String>) {
        let mut items: Vec<Target> = Vec::new();
        let mut rejected = Vec::new();

        for line in lines {
            let cleaned = clean(line);
            if cleaned.is_empty() {
                continue;
            }
            match classify(&cleaned) {
                Some(kind) => {
                    let target = Target {
                        value: cleaned,
                        kind,
                    };
                    // Повторы в списке — обычное дело при вставке из нескольких
                    // мест; проверять одно и то же дважды незачем.
                    if !items.iter().any(|t| t.value == target.value) && items.len() < MAX {
                        items.push(target);
                    }
                }
                None => rejected.push(line.trim().to_string()),
            }
        }

        (Self { items }, rejected)
    }

    /// Текст для поля ввода.
    pub fn to_text(&self) -> String {
        self.items
            .iter()
            .map(|t| t.value.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

}

/// Приводит строку к виду, пригодному для проверки.
///
/// Люди вставляют ссылки целиком, вместе с протоколом, путём и знаками
/// препинания. Требовать «чистое имя» значило бы перекладывать на человека
/// работу, которую программа делает за пару строк.
fn clean(line: &str) -> String {
    let mut s = line.trim();
    if s.starts_with('#') {
        return String::new();
    }
    for prefix in ["https://", "http://", "//"] {
        s = s.strip_prefix(prefix).unwrap_or(s);
    }
    // Отрезаем путь, порт, параметры и учётные данные.
    s = s.split(['/', '?', '#']).next().unwrap_or(s);
    if let Some(rest) = s.rsplit('@').next() {
        s = rest;
    }
    // Порт отбрасываем только у имён: у адреса двоеточий не бывает.
    if let Some((host, port)) = s.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            s = host;
        }
    }
    s.trim_end_matches('.').trim().to_lowercase()
}

/// Определяет, адрес это или имя. Всё, что не похоже ни на то, ни на другое,
/// отвергается — лучше сказать человеку, что строка не понята, чем потом
/// показать непонятную ошибку сети.
fn classify(value: &str) -> Option<Kind> {
    if let Ok(addr) = value.parse::<Ipv4Addr>() {
        return Some(Kind::Address(addr));
    }
    let looks_like_domain = value.len() >= 4
        && value.contains('.')
        && !value.starts_with('.')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    looks_like_domain.then_some(Kind::Domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_list_parses_completely() {
        let list = TargetList::default();
        assert_eq!(list.items().len(), DEFAULTS_LEN);
        assert!(list.items().iter().all(|t| t.is_domain()));
    }

    /// Без заведомо рабочих эталонов список бесполезен: «не открывается»
    /// не с чем сравнить, и отличить блокировку от обрыва связи нельзя.
    #[test]
    fn default_list_mixes_controls_with_problem_sites() {
        let list = TargetList::default();
        let has = |name: &str| list.items().iter().any(|t| t.value == name);
        assert!(has("ya.ru"), "нет эталона");
        assert!(has("gosuslugi.ru"), "нет эталона");
        assert!(has("instagram.com"), "нет проблемного сайта");
        assert!(has("telegram.org"), "нет проблемного сайта");
        assert!(DEFAULTS_LEN <= MAX, "список по умолчанию не должен упираться в предел");
    }

    /// Люди вставляют ссылки, а не имена. Требовать ручной чистки — значит
    /// перекладывать на человека работу программы.
    #[test]
    fn urls_are_reduced_to_host() {
        let (list, rejected) = TargetList::parse(
            "https://www.youtube.com/watch?v=123\n\
             http://example.com:8080/path\n\
             ya.ru.\n",
        );
        assert!(rejected.is_empty(), "неожиданно отвергнуто: {rejected:?}");
        assert_eq!(
            list.items().iter().map(|t| t.value.as_str()).collect::<Vec<_>>(),
            ["www.youtube.com", "example.com", "ya.ru"]
        );
    }

    #[test]
    fn addresses_and_domains_are_told_apart() {
        let (list, _) = TargetList::parse("1.1.1.1\ndiscord.com");
        assert_eq!(list.items()[0].kind, Kind::Address(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(list.items()[1].kind, Kind::Domain);
    }

    /// Непонятая строка обязана вернуться пользователю, а не исчезнуть.
    #[test]
    fn unparsable_lines_are_reported_back() {
        let (list, rejected) = TargetList::parse("ya.ru\nне сайт вовсе\n\n  \n");
        assert_eq!(list.items().len(), 1);
        assert_eq!(rejected, vec!["не сайт вовсе"]);
    }

    #[test]
    fn comments_and_blank_lines_are_skipped_silently() {
        let (list, rejected) = TargetList::parse("# мои сайты\nya.ru\n\n");
        assert_eq!(list.items().len(), 1);
        assert!(rejected.is_empty());
    }

    #[test]
    fn duplicates_are_collapsed() {
        let (list, _) = TargetList::parse("ya.ru\nhttps://ya.ru/\nYA.RU");
        assert_eq!(list.items().len(), 1);
    }

    #[test]
    fn list_is_capped() {
        let many: String = (0..MAX + 10)
            .map(|i| format!("site{i}.example\n"))
            .collect();
        let (list, _) = TargetList::parse(&many);
        assert_eq!(list.items().len(), MAX);
    }

    #[test]
    fn text_round_trips() {
        let (list, _) = TargetList::parse("ya.ru\n1.1.1.1");
        let (again, _) = TargetList::parse(&list.to_text());
        assert_eq!(list, again);
    }
}
