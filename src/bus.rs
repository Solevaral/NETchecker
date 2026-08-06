//! Канал между фоновым движком диагностики и UI-потоком.
//!
//! Движок никогда не трогает egui напрямую: он только шлёт сюда события,
//! а окно разбирает их в начале каждого кадра. Благодаря этому интерфейс
//! остаётся отзывчивым, пока проверки висят на сетевых таймаутах.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;

use crate::model::{CheckResult, Diagnosis, NodeId};

/// Событие от движка к интерфейсу.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    /// Диагностика началась; `total` — сколько шагов запланировано.
    Started { total: usize },
    /// Проверка прервана по просьбе пользователя.
    Cancelled,
    /// Проверка запущена или завершена (UI обновляет строку по `result.id`).
    Check(Box<CheckResult>),
    /// Уточнение подписи и адреса узла схемы.
    Node {
        id: NodeId,
        subtitle: String,
        address: Option<String>,
    },
    /// Текст под прогресс-баром.
    Progress { done: usize, label: String },
    /// Диагностика завершена, вот вердикт.
    Finished(Box<Diagnosis>),
}

pub type EventTx = Sender<EngineEvent>;
pub type EventRx = Receiver<EngineEvent>;

/// Обёртка над отправителем: молча игнорирует закрытый канал.
///
/// Если пользователь закрыл окно посреди проверки, фоновому потоку незачем
/// падать с паникой — он просто доработает и завершится.
/// Признак «пользователь попросил прекратить».
///
/// Полная проверка занимает десятки секунд, и всё это время человек не должен
/// оставаться заложником запущенного конвейера. Проверки смотрят на этот флаг
/// между шагами: обрывать сетевую пробу на середине незачем, она всё равно
/// закончится через свой тайм-аут.
#[derive(Clone, Default)]
pub struct Cancel {
    flag: Arc<AtomicBool>,
}

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn requested(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }
}

#[derive(Clone)]
pub struct Reporter {
    tx: EventTx,
    cancel: Cancel,
}

impl Reporter {
    pub fn new(tx: EventTx, cancel: Cancel) -> Self {
        Self { tx, cancel }
    }

    /// Просили ли прекратить проверку.
    pub fn cancelled(&self) -> bool {
        self.cancel.requested()
    }

    pub fn send(&self, event: EngineEvent) {
        let _ = self.tx.send(event);
    }

    pub fn check(&self, result: CheckResult) {
        self.send(EngineEvent::Check(Box::new(result)));
    }

    pub fn node(&self, id: NodeId, subtitle: impl Into<String>, address: Option<String>) {
        self.send(EngineEvent::Node {
            id,
            subtitle: subtitle.into(),
            address,
        });
    }

    pub fn progress(&self, done: usize, label: impl Into<String>) {
        self.send(EngineEvent::Progress {
            done,
            label: label.into(),
        });
    }
}
