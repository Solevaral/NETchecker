//! Фоновое наблюдение за связью.
//!
//! Разовая диагностика отвечает на вопрос «что сейчас», но самые неприятные
//! проблемы — плавающие: связь пропадает на минуту раз в час, и в момент
//! проверки всё оказывается в порядке. Поймать такое можно только наблюдением.
//!
//! Замеры складываются в кольцевой буфер, а переходы «работает — не работает»
//! пишутся в журнал обрывов: человеку нужны не цифры, а ответ на вопрос
//! «когда и надолго ли пропадало».
//!
//! Состояние живёт в общей памяти, а не приходит событиями: и окно, и значок
//! в трее спрашивают одно и то же — «как дела сейчас», а не «что изменилось».

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::engine::icmp::{Pinger, ReplyKind};
use crate::engine::probe::tcp_connect;
use crate::privileged::Capabilities;

/// Сколько замеров держим. При интервале в 15 секунд это чуть больше двух
/// часов — достаточно, чтобы увидеть закономерность, и мало, чтобы не думать
/// о памяти.
const HISTORY: usize = 512;

/// Опорный узел наблюдения. Отдельно от списка целей: мониторинг следит
/// за самим фактом связи, а не за доступностью конкретных сайтов.
const ANCHOR: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

/// Доля потерь, начиная с которой связь считается нестабильной.
const LOSS_THRESHOLD: f32 = 0.2;

/// Во сколько раз задержка должна превысить обычную, чтобы это назвали
/// ухудшением. Двукратный скачок — это уже заметно на слух в разговоре.
const LATENCY_FACTOR: f32 = 3.0;

/// Один замер.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub at: SystemTime,
    /// Время отклика. `None` — ответа не было.
    pub rtt: Option<Duration>,
}

impl Sample {
    pub fn lost(&self) -> bool {
        self.rtt.is_none()
    }
}

/// Как оценивается связь прямо сейчас.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Наблюдение выключено или ещё не набрало данных.
    Unknown,
    Ok,
    /// Связь есть, но с потерями или скачками задержки.
    Degraded,
    /// Связи нет.
    Down,
}

impl Health {
    pub fn title(self) -> &'static str {
        match self {
            Health::Unknown => "нет данных",
            Health::Ok => "связь стабильна",
            Health::Degraded => "связь с перебоями",
            Health::Down => "связи нет",
        }
    }
}

/// Запись в журнале обрывов.
#[derive(Debug, Clone)]
pub struct Outage {
    pub started: SystemTime,
    /// `None` — обрыв продолжается.
    pub ended: Option<SystemTime>,
    /// Что удалось выяснить о причине в момент обрыва.
    pub reason: String,
}

impl Outage {
    pub fn duration(&self) -> Option<Duration> {
        self.ended
            .and_then(|end| end.duration_since(self.started).ok())
    }
}

/// То, что видят окно и значок в трее.
#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub samples: Vec<Sample>,
    pub outages: Vec<Outage>,
    pub health: Health,
    /// Короткая строка для подсказки над значком в трее.
    pub summary: String,
}

impl Default for Health {
    fn default() -> Self {
        Health::Unknown
    }
}

#[derive(Default)]
struct State {
    samples: VecDeque<Sample>,
    outages: Vec<Outage>,
    health: Health,
    summary: String,
}

/// Наблюдатель. Поток живёт ровно пока включён.
pub struct Monitor {
    state: Arc<Mutex<State>>,
    running: Arc<AtomicBool>,
    interval: Arc<AtomicU64>,
    caps: Capabilities,
}

impl Monitor {
    pub fn new(caps: Capabilities, interval: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::default())),
            running: Arc::new(AtomicBool::new(false)),
            interval: Arc::new(AtomicU64::new(interval)),
            caps,
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn set_interval(&self, seconds: u64) {
        self.interval.store(seconds, Ordering::Relaxed);
    }

    pub fn start(&self) {
        // Смена false -> true и запуск потока одной операцией: иначе два
        // быстрых нажатия подряд подняли бы два потока.
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let state = Arc::clone(&self.state);
        let running = Arc::clone(&self.running);
        let interval = Arc::clone(&self.interval);
        let caps = self.caps;

        std::thread::spawn(move || {
            let pinger = Pinger::new(caps);
            while running.load(Ordering::Relaxed) {
                let sample = probe(pinger.as_ref());
                {
                    let mut state = state.lock().expect("состояние наблюдения");
                    state.push(sample);
                }

                // Ждём дробно, чтобы выключение срабатывало сразу, а не через
                // весь интервал: человек нажал «выключить» и ждёт результата.
                let seconds = interval.load(Ordering::Relaxed).max(1);
                for _ in 0..seconds * 4 {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        });
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        let mut state = self.state.lock().expect("состояние наблюдения");
        state.health = Health::Unknown;
        state.summary = "наблюдение выключено".to_string();
        // Незакрытый обрыв закрываем: он кончился не потому, что связь
        // восстановилась, а потому что мы перестали смотреть.
        if let Some(last) = state.outages.last_mut() {
            if last.ended.is_none() {
                last.ended = Some(SystemTime::now());
                last.reason
                    .push_str(" (наблюдение выключено до восстановления)");
            }
        }
    }

    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().expect("состояние наблюдения");
        Snapshot {
            samples: state.samples.iter().copied().collect(),
            outages: state.outages.clone(),
            health: state.health,
            summary: state.summary.clone(),
        }
    }
}

impl State {
    fn push(&mut self, sample: Sample) {
        if self.samples.len() == HISTORY {
            self.samples.pop_front();
        }
        self.samples.push_back(sample);

        let previous = self.health;
        self.health = evaluate(&self.samples);
        self.summary = describe(&self.samples, self.health);

        // Журнал ведём по переходам, а не по каждому замеру: человеку нужен
        // список «когда пропадало», а не полторы тысячи строк.
        match (previous, self.health) {
            (before, Health::Down) if before != Health::Down => {
                self.outages.push(Outage {
                    started: sample.at,
                    ended: None,
                    reason: "нет ответа от интернета".to_string(),
                });
            }
            (Health::Down, after) if after != Health::Down => {
                if let Some(last) = self.outages.last_mut() {
                    if last.ended.is_none() {
                        last.ended = Some(sample.at);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Один замер связи.
fn probe(pinger: Option<&Pinger>) -> Sample {
    let at = SystemTime::now();

    if let Some(pinger) = pinger {
        let reply = pinger.ping(ANCHOR, 64, PROBE_TIMEOUT);
        if reply.kind == ReplyKind::Echo {
            return Sample {
                at,
                // Ноль означает «меньше миллисекунды», а не отсутствие замера.
                rtt: Some(reply.rtt.unwrap_or_default()),
            };
        }
        return Sample { at, rtt: None };
    }

    // Без ICMP замеряем установку TCP-соединения. Число получается больше,
    // чем чистая задержка сети, зато сравнимо само с собой.
    let started = Instant::now();
    let outcome = tcp_connect(SocketAddr::new(IpAddr::V4(ANCHOR), 443), PROBE_TIMEOUT);
    Sample {
        at,
        rtt: outcome.is_open().then(|| started.elapsed()),
    }
}

/// Оценка по последним замерам.
///
/// Смотрим на окно, а не на последний замер: одна потеря — это норма жизни
/// сети, и объявлять по ней обрыв значило бы дёргать человека попусту.
fn evaluate(samples: &VecDeque<Sample>) -> Health {
    let window: Vec<&Sample> = samples.iter().rev().take(10).collect();
    if window.is_empty() {
        return Health::Unknown;
    }

    let lost = window.iter().filter(|s| s.lost()).count();

    // Две потери подряд — это уже не случайность.
    if window.iter().take(2).filter(|s| s.lost()).count() == 2 || lost == window.len() {
        return Health::Down;
    }

    if (lost as f32 / window.len() as f32) > LOSS_THRESHOLD {
        return Health::Degraded;
    }

    // Скачок задержки ищем относительно привычной для этого канала, а не
    // относительно абстрактного «хорошего» значения: у спутника и у оптики
    // нормы разные.
    if let (Some(typical), Some(recent)) = (median_rtt(samples), window[0].rtt) {
        if typical > Duration::ZERO && recent.as_secs_f32() > typical.as_secs_f32() * LATENCY_FACTOR
        {
            return Health::Degraded;
        }
    }

    Health::Ok
}

fn median_rtt(samples: &VecDeque<Sample>) -> Option<Duration> {
    let mut values: Vec<Duration> = samples.iter().filter_map(|s| s.rtt).collect();
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    Some(values[values.len() / 2])
}

fn describe(samples: &VecDeque<Sample>, health: Health) -> String {
    let total = samples.len();
    if total == 0 {
        return "наблюдение только началось".to_string();
    }
    let lost = samples.iter().filter(|s| s.lost()).count();
    let last = samples.back().and_then(|s| s.rtt);

    match health {
        Health::Down => format!("связи нет, потерь {lost} из {total}"),
        _ => match last {
            Some(rtt) => format!(
                "{}, потерь {lost} из {total}",
                crate::engine::trace::format_rtt(rtt)
            ),
            None => format!("последний запрос без ответа, потерь {lost} из {total}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(rtt: Option<u64>) -> Sample {
        Sample {
            at: SystemTime::now(),
            rtt: rtt.map(Duration::from_millis),
        }
    }

    fn state_with(rtts: &[Option<u64>]) -> State {
        let mut state = State::default();
        for r in rtts {
            state.push(sample(*r));
        }
        state
    }

    /// Одна потеря — обычная жизнь сети. Объявлять по ней обрыв значило бы
    /// дёргать человека попусту.
    #[test]
    fn single_loss_is_not_an_outage() {
        let state = state_with(&[Some(20), Some(21), None, Some(20), Some(19)]);
        assert_eq!(state.health, Health::Ok);
        assert!(state.outages.is_empty());
    }

    #[test]
    fn two_losses_in_a_row_are_an_outage() {
        let state = state_with(&[Some(20), Some(21), None, None]);
        assert_eq!(state.health, Health::Down);
        assert_eq!(state.outages.len(), 1);
        assert!(state.outages[0].ended.is_none(), "обрыв ещё продолжается");
    }

    /// Обрыв закрывается сразу, как только пошли ответы. Оценка при этом
    /// ещё держится на «с перебоями»: потери никуда не делись, они лежат
    /// в окне последних замеров, и объявлять связь исправной рано.
    #[test]
    fn recovery_closes_the_outage_but_keeps_the_warning() {
        let state = state_with(&[Some(20), None, None, Some(22), Some(21), Some(20)]);
        assert_eq!(state.health, Health::Degraded);
        assert_eq!(state.outages.len(), 1);
        assert!(state.outages[0].ended.is_some(), "обрыв должен быть закрыт");
    }

    /// Когда потери уходят из окна, связь снова считается исправной —
    /// иначе одна давняя авария навсегда красила бы значок жёлтым.
    #[test]
    fn health_returns_to_ok_once_losses_leave_the_window() {
        let mut rtts = vec![Some(20), None, None];
        rtts.extend((0..12).map(|_| Some(20)));
        let state = state_with(&rtts);
        assert_eq!(state.health, Health::Ok);
        assert_eq!(state.outages.len(), 1);
        assert!(state.outages[0].ended.is_some());
    }

    /// Скачок задержки оценивается относительно привычной для этого канала:
    /// у спутника 600 мс — норма, а у оптики — авария.
    #[test]
    fn latency_spike_is_relative_to_the_usual() {
        let mut rtts: Vec<Option<u64>> = (0..10).map(|_| Some(20)).collect();
        rtts.push(Some(200));
        assert_eq!(state_with(&rtts).health, Health::Degraded);

        let slow: Vec<Option<u64>> = (0..10).map(|_| Some(600)).collect();
        assert_eq!(state_with(&slow).health, Health::Ok);
    }

    #[test]
    fn history_does_not_grow_without_bound() {
        let rtts: Vec<Option<u64>> = (0..HISTORY + 50).map(|_| Some(20)).collect();
        assert_eq!(state_with(&rtts).samples.len(), HISTORY);
    }

    /// Выключение наблюдения не должно оставлять в журнале вечно открытый
    /// обрыв: он кончился не потому, что связь вернулась.
    #[test]
    fn stopping_closes_a_dangling_outage() {
        let monitor = Monitor::new(
            Capabilities {
                icmp: crate::privileged::IcmpBackend::Fallback,
                elevated: false,
            },
            15,
        );
        {
            let mut state = monitor.state.lock().unwrap();
            state.push(sample(Some(20)));
            state.push(sample(None));
            state.push(sample(None));
            assert!(state.outages[0].ended.is_none());
        }
        monitor.stop();
        let snapshot = monitor.snapshot();
        assert!(snapshot.outages[0].ended.is_some());
        assert_eq!(snapshot.health, Health::Unknown);
    }
}
