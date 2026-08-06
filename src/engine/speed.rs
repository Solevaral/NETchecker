//! Замер скорости и поиск замедления.
//!
//! Замедление трудно поймать одним числом: «10 Мбит/с» само по себе не хорошо
//! и не плохо, всё зависит от тарифа. Зато оно хорошо видно в сравнении —
//! когда до одной точки скорость нормальная, а до другой при такой же
//! задержке в разы ниже. Односторонняя просадка означает, что дело не в вашем
//! канале: он бы просел одинаково ко всем.
//!
//! Второй признак — «быстрое соединение, медленная передача»: соединение
//! устанавливается мгновенно, а данные идут еле-еле. Перегруженный канал так
//! себя не ведёт, там растёт и задержка.

use std::io::Read;
use std::time::{Duration, Instant};

/// Сколько байтов качаем. Достаточно, чтобы разгон соединения перестал влиять
/// на результат, и мало, чтобы не тратить трафик человека впустую.
const PAYLOAD_BYTES: usize = 2_000_000;

const TIMEOUT: Duration = Duration::from_secs(12);

/// Точки замера. Разные сети и разные страны — именно на различии между ними
/// и строится вывод.
const ENDPOINTS: [(&str, &str); 2] = [
    (
        "Cloudflare",
        "https://speed.cloudflare.com/__down?bytes=2000000",
    ),
    // Именно 10Mb: файл на 1Mb — это один мегабит, около 128 килобайт.
    // На таком объёме соединение не успевает разогнаться, и замер вышел бы
    // заниженным просто из-за размера.
    ("OVH", "https://proof.ovh.net/files/10Mb.dat"),
];

/// Меньше этого объёма замер не считается: на коротком куске измеряется
/// не скорость канала, а разгон соединения.
const MIN_BYTES: usize = 700_000;

/// Результат одного замера.
#[derive(Debug, Clone)]
pub struct Measurement {
    pub name: String,
    /// Скорость в мегабитах в секунду.
    pub mbps: Option<f64>,
    /// Сколько занял отклик до первых данных.
    pub first_byte: Option<Duration>,
    pub note: Option<String>,
}

impl Measurement {
    pub fn describe(&self) -> String {
        match self.mbps {
            Some(mbps) => {
                let ttfb = self
                    .first_byte
                    .map(|d| format!(", первые данные через {} мс", d.as_millis()))
                    .unwrap_or_default();
                format!("{}: {mbps:.1} Мбит/с{ttfb}", self.name)
            }
            None => format!(
                "{}: замер не удался{}",
                self.name,
                self.note
                    .as_ref()
                    .map(|n| format!(" ({n})"))
                    .unwrap_or_default()
            ),
        }
    }
}

/// Вывод по всем замерам.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Замерить не удалось.
    Unavailable,
    /// Скорость ровная.
    Even { best: f64 },
    /// Скорости заметно разные, но разницу объясняет расстояние: до дальней
    /// точки и задержка больше. По таким данным вывода о замедлении не сделать.
    Inconclusive {
        best: f64,
        slow: String,
        slow_mbps: f64,
        latency_ratio: f64,
    },
    /// К одной из точек скорость заметно ниже.
    Uneven { fast: String, slow: String, ratio: f64 },
    /// Соединение устанавливается быстро, а данные идут медленно.
    SlowBody { name: String, mbps: f64 },
}

/// Во сколько раз должна отличаться скорость, чтобы говорить о просадке.
///
/// Точки замера физически разные, и двукратная разница между ними — норма.
/// Четырёхкратная — уже не объясняется географией.
const UNEVEN_FACTOR: f64 = 4.0;

/// Скорость, ниже которой при быстром отклике речь идёт уже об ограничении,
/// а не о загруженности канала.
const SLOW_MBPS: f64 = 2.0;

/// Во сколько раз задержки до точек замера могут отличаться, чтобы скорости
/// оставались сравнимыми между собой.
const LATENCY_TOLERANCE: f64 = 2.0;

pub fn run(agent: &ureq::Agent) -> (Vec<Measurement>, Verdict) {
    let measurements: Vec<Measurement> = ENDPOINTS
        .iter()
        .map(|(name, url)| measure(agent, name, url))
        .collect();

    (measurements.clone(), judge(&measurements))
}

fn judge(measurements: &[Measurement]) -> Verdict {
    let mut ok: Vec<(&Measurement, f64)> = measurements
        .iter()
        .filter_map(|m| m.mbps.map(|v| (m, v)))
        .collect();

    if ok.is_empty() {
        return Verdict::Unavailable;
    }
    ok.sort_by(|a, b| b.1.total_cmp(&a.1));

    let (fastest, best) = ok[0];

    if let Some(&(slowest, worst)) = ok.last() {
        // Разницу в скорости можно ставить в вину фильтрации только при
        // сопоставимой задержке. Пропускная способность TCP обратно
        // пропорциональна времени оборота: до вдвое более далёкой точки
        // скорость честно вдвое ниже, и никто её не «режет».
        let comparable = match (fastest.first_byte, slowest.first_byte) {
            (Some(near), Some(far)) => far.as_secs_f64() < near.as_secs_f64() * LATENCY_TOLERANCE,
            _ => false,
        };

        if ok.len() > 1 && worst > 0.0 && best / worst >= UNEVEN_FACTOR {
            if comparable {
                return Verdict::Uneven {
                    fast: fastest.name.clone(),
                    slow: slowest.name.clone(),
                    ratio: best / worst,
                };
            }
            // Скорости разные, но и задержки разные. Назвать это ровной
            // скоростью нельзя — это было бы неправдой; назвать замедлением
            // тоже нельзя — разницу объясняет расстояние.
            let latency_ratio = match (fastest.first_byte, slowest.first_byte) {
                (Some(near), Some(far)) if near > Duration::ZERO => {
                    far.as_secs_f64() / near.as_secs_f64()
                }
                _ => 0.0,
            };
            return Verdict::Inconclusive {
                best,
                slow: slowest.name.clone(),
                slow_mbps: worst,
                latency_ratio,
            };
        }
    }

    // «Быстро ответил, медленно отдаёт» — картина именно ограничения:
    // при обычной перегрузке вместе со скоростью растёт и время отклика.
    for (m, mbps) in &ok {
        let quick = m
            .first_byte
            .is_some_and(|d| d < Duration::from_millis(150));
        if quick && *mbps < SLOW_MBPS {
            return Verdict::SlowBody {
                name: m.name.clone(),
                mbps: *mbps,
            };
        }
    }

    Verdict::Even { best }
}

fn measure(agent: &ureq::Agent, name: &str, url: &str) -> Measurement {
    let started = Instant::now();
    let response = match agent.get(url).call() {
        Ok(r) => r,
        Err(e) => {
            return Measurement {
                name: name.to_string(),
                mbps: None,
                first_byte: None,
                note: Some(e.to_string()),
            }
        }
    };

    let mut reader = response.into_body().into_reader();
    let mut buf = [0u8; 32 * 1024];
    let mut total = 0usize;
    let mut first_byte = None;
    // Время считаем от первых данных, а не от начала запроса: иначе в
    // «скорость» попадёт установка соединения, и на коротком файле она же
    // и определит результат.
    let mut transfer_started = None;

    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if first_byte.is_none() {
                    first_byte = Some(started.elapsed());
                    transfer_started = Some(Instant::now());
                }
                total += n;
                if total >= PAYLOAD_BYTES || started.elapsed() > TIMEOUT {
                    break;
                }
            }
            Err(e) => {
                if total == 0 {
                    return Measurement {
                        name: name.to_string(),
                        mbps: None,
                        first_byte,
                        note: Some(e.to_string()),
                    };
                }
                break;
            }
        }
    }

    let elapsed = transfer_started.map(|t| t.elapsed()).unwrap_or_default();
    let enough = total >= MIN_BYTES && elapsed > Duration::from_millis(50);
    let mbps = enough.then(|| total as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0);

    Measurement {
        name: name.to_string(),
        mbps,
        first_byte,
        note: (!enough).then(|| {
            format!("получено {} КБ — слишком мало для замера", total / 1024)
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str, mbps: Option<f64>, ttfb_ms: Option<u64>) -> Measurement {
        Measurement {
            name: name.into(),
            mbps,
            first_byte: ttfb_ms.map(Duration::from_millis),
            note: None,
        }
    }

    #[test]
    fn similar_speeds_are_even() {
        let verdict = judge(&[m("A", Some(90.0), Some(30)), m("B", Some(60.0), Some(40))]);
        assert!(matches!(verdict, Verdict::Even { .. }));
    }

    /// Далёкая точка честно отдаёт медленнее: пропускная способность TCP
    /// обратно пропорциональна времени оборота. Ставить это в вину
    /// фильтрации — значит обвинять географию.
    #[test]
    fn distant_endpoint_is_not_called_throttled() {
        let verdict = judge(&[
            m("Близкая", Some(114.0), Some(160)),
            m("Далёкая", Some(2.1), Some(424)),
        ]);
        // И «ровная скорость» здесь было бы враньём, и «замедление» —
        // домыслом. Честный ответ: по этим данным вывода не сделать.
        assert!(
            matches!(verdict, Verdict::Inconclusive { .. }),
            "получено {verdict:?}"
        );
    }

    /// Односторонняя просадка — признак того, что дело не в канале:
    /// свой канал просел бы одинаково ко всем точкам.
    #[test]
    fn one_sided_drop_is_reported() {
        let verdict = judge(&[m("Быстрая", Some(80.0), Some(30)), m("Медленная", Some(5.0), Some(30))]);
        match verdict {
            Verdict::Uneven { fast, slow, ratio } => {
                assert_eq!(fast, "Быстрая");
                assert_eq!(slow, "Медленная");
                assert!(ratio >= UNEVEN_FACTOR);
            }
            other => panic!("ожидалась просадка, получено {other:?}"),
        }
    }

    /// Медленно везде одинаково — это тариф или загруженный канал,
    /// а не избирательное ограничение.
    #[test]
    fn uniformly_slow_link_is_not_called_throttling() {
        let verdict = judge(&[m("A", Some(3.0), Some(300)), m("B", Some(2.5), Some(320))]);
        assert!(matches!(verdict, Verdict::Even { .. }));
    }

    #[test]
    fn quick_answer_with_slow_transfer_is_flagged() {
        let verdict = judge(&[m("A", Some(0.6), Some(20))]);
        assert!(matches!(verdict, Verdict::SlowBody { .. }));
    }

    #[test]
    fn no_successful_measurements_means_unavailable() {
        assert!(matches!(
            judge(&[m("A", None, None)]),
            Verdict::Unavailable
        ));
    }
}
