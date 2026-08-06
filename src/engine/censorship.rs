//! Разбор блокировок: что именно мешает открыть сайт.
//!
//! Главная задача здесь — не «поймать блокировку», а **не перепутать**. Одно и
//! то же внешнее проявление («сайт не открывается») бывает у четырёх разных
//! причин: сайт лежит, адрес заблокирован, подменён DNS, фильтр читает имя
//! сайта. Лечатся они по-разному, поэтому и назвать их надо по-разному.
//!
//! Все выводы строятся на сравнении, а не на списках «запрещённых» адресов:
//! программа меняет ровно один параметр пробы и смотрит, изменится ли
//! поведение. Такой подход не устаревает вместе с реестрами и одинаково
//! работает у любого провайдера.

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::engine::dns::Answer;
use crate::engine::tls::Outcome;

/// Что происходит с конкретным сайтом.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Открывается.
    Reachable,
    /// Ответ DNS не совпадает с настоящим: адрес подменён.
    DnsSpoofed,
    /// Соединение обрывается именно из-за имени сайта.
    NameFiltered,
    /// Не пускает сам адрес: до него не доходят пакеты.
    AddressBlocked,
    /// Вместо сайта отдают страницу с сообщением о блокировке.
    StubPage,
    /// Соединение вскрывают: предъявлен чужой сертификат.
    CertificateSwapped,
    /// Похоже, сайт действительно недоступен — фильтрация ни при чём.
    SiteDown,
    /// Данных не хватило.
    Unclear,
}

impl Verdict {
    pub fn headline(self) -> &'static str {
        match self {
            Verdict::Reachable => "открывается",
            Verdict::DnsSpoofed => "подменён адрес",
            Verdict::NameFiltered => "блокировка по имени сайта",
            Verdict::AddressBlocked => "блокировка по адресу",
            Verdict::StubPage => "подставлена страница-заглушка",
            Verdict::CertificateSwapped => "подменён сертификат",
            Verdict::SiteDown => "сайт не отвечает",
            Verdict::Unclear => "не удалось определить",
        }
    }
}

/// Всё, что удалось собрать по одному сайту.
#[derive(Debug, Clone)]
pub struct Probe {
    pub domain: String,
    /// Что ответил резолвер, назначенный системой.
    pub system_dns: Option<Answer>,
    /// Что ответил DoH — он же эталон: провайдер этот ответ подменить не может.
    pub doh: Option<Answer>,
    /// Адрес, к которому шли пробы TLS (берётся из DoH, если он ответил).
    pub address: Option<Ipv4Addr>,
    /// Сколько занимает установка TCP-соединения с этим адресом.
    /// Это физический предел: быстрее сам сервер ответить не может.
    pub baseline: Option<Duration>,
    /// Рукопожатие с настоящим именем сайта.
    pub real_sni: Option<Outcome>,
    /// То же соединение, но с нейтральным именем.
    pub neutral_sni: Option<Outcome>,
    /// Настоящее имя, но пакет отправлен двумя частями.
    pub split_sni: Option<Outcome>,
    /// Сертификат, который предъявил сервер.
    pub certificate: Option<crate::engine::cert::Info>,
    /// Ответ по незащищённому HTTP и вывод о том, заглушка это или нет.
    pub http: Option<crate::engine::http::Response>,
    pub http_stub: Option<String>,
}

impl Probe {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            system_dns: None,
            doh: None,
            address: None,
            baseline: None,
            real_sni: None,
            neutral_sni: None,
            split_sni: None,
            certificate: None,
            http: None,
            http_stub: None,
        }
    }
}

/// Вывод по одному сайту.
#[derive(Debug, Clone)]
pub struct Finding {
    pub domain: String,
    pub verdict: Verdict,
    pub simple: String,
    pub expert: String,
    pub evidence: Vec<String>,
}

/// Разбирает один сайт.
pub fn judge(p: &Probe) -> Finding {
    let mut evidence = Vec::new();

    if let Some(a) = &p.system_dns {
        evidence.push(format!("DNS системы: {}", a.describe()));
    }
    if let Some(a) = &p.doh {
        evidence.push(format!("DNS по HTTPS (эталон): {}", a.describe()));
    }
    if let Some(o) = &p.real_sni {
        evidence.push(format!("рукопожатие с именем {}: {}", p.domain, o.describe()));
    }
    if let Some(o) = &p.neutral_sni {
        evidence.push(format!("то же соединение с нейтральным именем: {}", o.describe()));
    }
    if let Some(o) = &p.split_sni {
        evidence.push(format!("имя разбито на две части: {}", o.describe()));
    }
    if let Some(b) = p.baseline {
        evidence.push(format!(
            "время установки соединения с сервером: {} мс",
            b.as_millis()
        ));
    }
    if let Some(cert) = &p.certificate {
        evidence.push(format!("сертификат: {}", cert.describe()));
    }
    if let Some(response) = &p.http {
        evidence.push(format!("ответ по HTTP: {}", response.describe()));
    }

    let make = |verdict: Verdict, simple: String, expert: String| Finding {
        domain: p.domain.clone(),
        verdict,
        simple,
        expert,
        evidence: evidence.clone(),
    };

    // 1. Подмена DNS. Проверяется первой: если адрес подменён, все дальнейшие
    //    пробы шли бы не к тому серверу и ничего не значили бы.
    if let (Some(sys), Some(doh)) = (&p.system_dns, &p.doh) {
        if sys.is_blackhole() && !doh.is_blackhole() {
            return make(
                Verdict::DnsSpoofed,
                format!(
                    "Ваш DNS-сервер отвечает, что сайт {} находится «в никуда». \
                     Настоящий адрес существует — значит ответ подменили.",
                    p.domain
                ),
                format!(
                    "Системный резолвер вернул {}, DoH — {}.",
                    sys.describe(),
                    doh.describe()
                ),
            );
        }
        if sys.is_empty() && !doh.is_empty() && sys.rcode != 0 {
            return make(
                Verdict::DnsSpoofed,
                format!(
                    "Ваш DNS-сервер говорит, что сайта {} не существует, хотя на самом деле \
                     он есть.",
                    p.domain
                ),
                format!(
                    "Системный резолвер: код {} ({}). DoH вернул {} адрес(ов).",
                    sys.rcode,
                    crate::engine::dns::rcode_name(sys.rcode),
                    doh.addresses.len()
                ),
            );
        }
    }

    // 2. Подмена сертификата. Проверяется раньше проб по имени: если
    //    соединение вскрывают, оно как раз *устанавливается*, и по одним
    //    только пробам сайт выглядел бы работающим.
    if let Some(cert) = &p.certificate {
        if !cert.covers(&p.domain) {
            let reason = if cert.self_signed() {
                "Сертификат выписан сам себе"
            } else {
                "Сертификат выдан на другое имя"
            };
            return make(
                Verdict::CertificateSwapped,
                format!(
                    "Соединение с {} кто-то вскрывает: сервер предъявляет не тот сертификат. \
                     Всё, что вы отправите на этот сайт, видно посреднику.",
                    p.domain
                ),
                format!("{reason}: {}.", cert.describe()),
            );
        }
    }

    // 3. Страница-заглушка вместо сайта.
    if let Some(reason) = &p.http_stub {
        return make(
            Verdict::StubPage,
            format!(
                "Вместо сайта {} отдают страницу с сообщением о блокировке. Сайт при этом \
                 может быть полностью исправен — ответ подставили по дороге.",
                p.domain
            ),
            format!(
                "Запрос по HTTP с именем {} вернул заглушку: {reason}.",
                p.domain
            ),
        );
    }

    let (Some(real), Some(neutral)) = (&p.real_sni, &p.neutral_sni) else {
        return make(
            Verdict::Unclear,
            format!("Проверить сайт {} не удалось.", p.domain),
            "Не хватает результатов проб TLS.".to_string(),
        );
    };

    // 4. Фильтрация по имени. Тот же адрес, тот же порт, отличается только имя
    //    в первом пакете — если разница есть, дело именно в имени.
    if real.is_broken() && neutral.is_answered() {
        let split_helped = p.split_sni.as_ref().is_some_and(Outcome::is_answered);
        let injected = looks_injected(real, p.baseline);

        let mut expert = format!(
            "На один и тот же адрес: с именем {} — {}, с нейтральным именем — {}.",
            p.domain,
            real.describe(),
            neutral.describe()
        );
        if split_helped {
            expert.push_str(
                " При отправке имени двумя частями соединение проходит — значит имя читает \
                 промежуточное оборудование, а не сервер: серверу безразлично, сколькими \
                 кусками пришли данные.",
            );
        }
        if injected {
            expert.push_str(
                " Обрыв пришёл быстрее, чем сервер физически успел бы ответить, — \
                 отвечал не он.",
            );
        }

        return make(
            Verdict::NameFiltered,
            format!(
                "Сайт {} блокируют по имени. Сервер жив и на тот же адрес отвечает — \
                 обрывается только соединение, в котором указано это имя.",
                p.domain
            ),
            expert,
        );
    }

    // 3. Не пускает адрес. Имя ни при чём: молчит любое соединение.
    if real.is_broken() && neutral.is_broken() {
        let both_timeout = matches!(real, Outcome::Timeout) && matches!(neutral, Outcome::Timeout);
        if both_timeout && p.baseline.is_none() {
            return make(
                Verdict::AddressBlocked,
                format!(
                    "До сервера сайта {} не доходят пакеты — ни с каким именем. \
                     Так выглядит блокировка по адресу.",
                    p.domain
                ),
                "Соединение не устанавливается ни с настоящим, ни с нейтральным именем, \
                 явного отказа нет — пакеты пропадают молча."
                    .to_string(),
            );
        }
        return make(
            Verdict::SiteDown,
            format!(
                "Сайт {} не отвечает, но признаков блокировки нет: он одинаково молчит \
                 на любое обращение. Скорее всего, дело в самом сайте.",
                p.domain
            ),
            format!(
                "Соединение устанавливается, но рукопожатие не проходит ни с настоящим \
                 именем ({}), ни с нейтральным ({}).",
                real.describe(),
                neutral.describe()
            ),
        );
    }

    make(
        Verdict::Reachable,
        format!("Сайт {} открывается нормально.", p.domain),
        format!("Рукопожатие прошло: {}.", real.describe()),
    )
}

/// Обрыв пришёл раньше, чем мог бы ответить сам сервер.
///
/// Расстояние до сервера известно: столько занимает установка TCP-соединения.
/// Ответ не может прийти существенно быстрее — если пришёл, его отправил
/// кто-то ближе, то есть оборудование по дороге.
fn looks_injected(outcome: &Outcome, baseline: Option<Duration>) -> bool {
    let (Some(reaction), Some(baseline)) = (outcome.latency(), baseline) else {
        return false;
    };
    // Половина времени установки соединения — заведомо недостижимый для
    // сервера срок, даже с поправкой на разброс задержек.
    baseline > Duration::from_millis(4) && reaction * 2 < baseline
}

/// Признаки того, что фильтрация стоит на транзите, а не у вас и не у сайта.
#[derive(Debug, Clone, Default)]
pub struct Transit {
    /// Сколько сайтов обрываются именно по имени.
    pub name_filtered: usize,
    /// На скольких обрыв пришёл быстрее физически возможного.
    pub injected: usize,
    /// На скольких помогает разделение пакета на части.
    pub split_helps: usize,
    /// Сколько сайтов проверено всего.
    pub total: usize,
}

impl Transit {
    /// Достаточно ли признаков, чтобы говорить о транзитном фильтре.
    ///
    /// Одного сайта мало: он мог просто сломаться. Уверенность даёт
    /// повторение одного и того же поведения на не связанных между собой
    /// сайтах — сломаться одинаково они не могли.
    pub fn is_confident(&self) -> bool {
        self.name_filtered >= 2 && (self.injected > 0 || self.split_helps > 0)
    }

    /// Есть ли вообще о чём говорить.
    pub fn has_signals(&self) -> bool {
        self.name_filtered > 0
    }

    pub fn simple(&self) -> String {
        if self.is_confident() {
            format!(
                "Соединения обрываются на оборудовании по дороге, а не у вас и не на стороне \
                 сайтов: одинаково перестают открываться {} не связанных между собой сайта, \
                 и обрыв приходит раньше, чем успел бы ответить сам сайт.",
                self.name_filtered
            )
        } else {
            format!(
                "Один сайт из {} обрывается по имени. Одного случая мало, чтобы утверждать \
                 что-то о фильтрации: сайт мог сломаться сам.",
                self.total
            )
        }
    }

    pub fn expert(&self) -> String {
        format!(
            "Проверено сайтов: {}. Обрыв зависит от имени: {}. Ответ пришёл быстрее \
             физически возможного: {}. Помогает разделение первого пакета: {}.",
            self.total, self.name_filtered, self.injected, self.split_helps
        )
    }
}

/// Сводит пробы по всем сайтам в признаки транзитной фильтрации.
pub fn transit_signals(probes: &[Probe], findings: &[Finding]) -> Transit {
    let mut t = Transit {
        total: probes.len(),
        ..Default::default()
    };

    for (probe, finding) in probes.iter().zip(findings) {
        if finding.verdict != Verdict::NameFiltered {
            continue;
        }
        t.name_filtered += 1;
        if probe
            .real_sni
            .as_ref()
            .is_some_and(|o| looks_injected(o, probe.baseline))
        {
            t.injected += 1;
        }
        if probe.split_sni.as_ref().is_some_and(Outcome::is_answered) {
            t.split_helps += 1;
        }
    }

    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(addrs: &[[u8; 4]], rcode: u8) -> Answer {
        Answer {
            addresses: addrs.iter().map(|a| Ipv4Addr::from(*a)).collect(),
            rcode,
            min_ttl: Some(300),
            elapsed: Duration::from_millis(5),
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn stub_answer_against_real_one_is_spoofing() {
        let mut p = Probe::new("example.com");
        p.system_dns = Some(answer(&[[0, 0, 0, 0]], 0));
        p.doh = Some(answer(&[[93, 184, 216, 34]], 0));
        assert_eq!(judge(&p).verdict, Verdict::DnsSpoofed);
    }

    #[test]
    fn nxdomain_from_system_but_not_from_doh_is_spoofing() {
        let mut p = Probe::new("example.com");
        p.system_dns = Some(answer(&[], 3));
        p.doh = Some(answer(&[[93, 184, 216, 34]], 0));
        assert_eq!(judge(&p).verdict, Verdict::DnsSpoofed);
    }

    /// Ключевое различение: сервер отвечает на тот же адрес с другим именем,
    /// значит он жив, а обрывается именно имя.
    #[test]
    fn broken_with_name_but_alive_without_it_is_name_filtering() {
        let mut p = Probe::new("example.com");
        p.address = Some(Ipv4Addr::new(93, 184, 216, 34));
        p.baseline = Some(ms(40));
        p.real_sni = Some(Outcome::Reset { after: ms(2) });
        p.neutral_sni = Some(Outcome::ServerHello { rtt: ms(45) });

        let f = judge(&p);
        assert_eq!(f.verdict, Verdict::NameFiltered);
        assert!(f.expert.contains("быстрее"), "инжект должен попасть в вывод");
    }

    /// Молчит одинаково на всё — это не блокировка по имени, и говорить
    /// о блокировке нельзя.
    #[test]
    fn silence_for_every_name_is_not_name_filtering() {
        let mut p = Probe::new("example.com");
        p.real_sni = Some(Outcome::Timeout);
        p.neutral_sni = Some(Outcome::Timeout);
        p.baseline = Some(ms(30));
        assert_eq!(judge(&p).verdict, Verdict::SiteDown);
    }

    #[test]
    fn working_site_is_reachable() {
        let mut p = Probe::new("ya.ru");
        p.real_sni = Some(Outcome::ServerHello { rtt: ms(12) });
        p.neutral_sni = Some(Outcome::Alert { rtt: ms(12), code: 112 });
        assert_eq!(judge(&p).verdict, Verdict::Reachable);
    }

    /// Быстрый ответ близкого сервера не должен считаться подделкой.
    #[test]
    fn nearby_server_is_not_mistaken_for_injection() {
        let fast = Outcome::Reset { after: ms(1) };
        assert!(!looks_injected(&fast, Some(ms(2))));
        assert!(looks_injected(&fast, Some(ms(60))));
    }

    /// Один сломанный сайт — ещё не фильтрация. Два несвязанных с одинаковым
    /// поведением — уже да.
    #[test]
    fn confidence_needs_more_than_one_site() {
        let one = Transit {
            name_filtered: 1,
            injected: 1,
            split_helps: 1,
            total: 5,
        };
        assert!(one.has_signals());
        assert!(!one.is_confident());

        let two = Transit {
            name_filtered: 2,
            ..one
        };
        assert!(two.is_confident());
    }
}
