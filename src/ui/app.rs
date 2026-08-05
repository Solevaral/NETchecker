//! Окно программы: панель управления, схема сети, вердикт и разбор по слоям.

use std::sync::mpsc::{self, TryRecvError};

use eframe::egui::{self, Color32, CornerRadius, RichText, ScrollArea, Stroke, StrokeKind};

use crate::bus::{EngineEvent, EventRx, EventTx, Reporter};
use crate::engine;
use crate::model::{Layer, NodeId, Report, Status};
use crate::privileged::Capabilities;
use crate::ui::{theme, topology};

/// Какой из разделов открыт.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Overview,
    Layers,
    About,
}

pub struct App {
    caps: Capabilities,
    tx: EventTx,
    rx: EventRx,
    report: Report,
    running: bool,
    total: usize,
    done: usize,
    progress_label: String,
    /// Экспертный режим меняет текст описаний, но не прячет проверки.
    expert: bool,
    tab: Tab,
    /// Узел схемы, по которому кликнули: фильтрует список проверок.
    focus: Option<NodeId>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        let (tx, rx) = mpsc::channel();
        let caps = Capabilities::detect();

        let mut app = Self {
            caps,
            tx,
            rx,
            report: Report::new(),
            running: false,
            total: 0,
            done: 0,
            progress_label: String::new(),
            expert: false,
            tab: Tab::Overview,
            focus: None,
        };
        // Первую проверку запускаем сразу: человек открыл программу именно
        // затем, чтобы узнать, что со связью.
        app.start();
        app
    }

    fn start(&mut self) {
        if self.running {
            return;
        }
        self.report = Report::new();
        self.running = true;
        self.done = 0;
        self.total = 0;
        self.progress_label = "Запускаю проверку…".to_string();
        self.focus = None;
        engine::spawn(self.caps, Reporter::new(self.tx.clone()));
    }

    /// Разбор накопившихся событий движка. Вызывается раз в кадр.
    fn drain_events(&mut self) {
        loop {
            match self.rx.try_recv() {
                Ok(EngineEvent::Started { total }) => self.total = total,
                Ok(EngineEvent::Check(result)) => self.report.apply(*result),
                Ok(EngineEvent::Node {
                    id,
                    subtitle,
                    address,
                }) => {
                    let node = self.report.node_mut(id);
                    node.subtitle = subtitle;
                    if address.is_some() {
                        node.address = address;
                    }
                }
                Ok(EngineEvent::Progress { done, label }) => {
                    self.done = done;
                    self.progress_label = label;
                }
                Ok(EngineEvent::Finished(diagnosis)) => {
                    self.report.diagnosis = *diagnosis;
                    self.running = false;
                }
                Err(TryRecvError::Empty) => break,
                // Отправитель исчез вместе с фоновым потоком — это норма
                // между запусками, канал живёт вместе с приложением.
                Err(TryRecvError::Disconnected) => break,
            }
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Netchecker");
            ui.add_space(4.0);
            ui.label(
                RichText::new("диагностика подключения по уровням OSI")
                    .color(theme::TEXT_DIM)
                    .small(),
            );

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let label = if self.running {
                    "Идёт проверка…"
                } else {
                    "Проверить"
                };
                if ui
                    .add_enabled(!self.running, egui::Button::new(label))
                    .clicked()
                {
                    self.start();
                }
                ui.checkbox(&mut self.expert, "Экспертный режим");
            });
        });

        ui.horizontal(|ui| {
            for (tab, name) in [
                (Tab::Overview, "Схема и вывод"),
                (Tab::Layers, "Уровни OSI"),
                (Tab::About, "О программе"),
            ] {
                if ui.selectable_label(self.tab == tab, name).clicked() {
                    self.tab = tab;
                }
            }
        });
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        self.bypass_banner(ui);

        if let Some(node) = topology::show(ui, &self.report) {
            self.focus = if self.focus == Some(node) {
                None
            } else {
                Some(node)
            };
            self.tab = Tab::Layers;
        }

        ui.add_space(6.0);
        self.verdict_card(ui);
    }

    /// Полоса с найденными VPN, прокси и средствами обхода.
    ///
    /// Показывается над схемой, а не в общем списке проверок, потому что она
    /// меняет смысл всего остального: если трафик уходит в туннель, схема
    /// описывает канал туннеля, а не подключение пользователя.
    fn bypass_banner(&self, ui: &mut egui::Ui) {
        let Some(check) = self.report.checks.iter().find(|c| c.id == "l2.bypass") else {
            return;
        };

        let color = theme::status_color(check.status);
        card(ui, color, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Обходы и туннели").color(color).strong());
                ui.label(
                    RichText::new(format!("[{}]", check.status.glyph()))
                        .color(color)
                        .small(),
                );
            });
            ui.add_space(2.0);
            ui.label(RichText::new(&check.simple).color(theme::TEXT));

            // Каждая находка отдельной строкой: человеку важно видеть, что
            // именно нашли и по какому признаку.
            for line in &check.evidence {
                ui.label(RichText::new(format!("• {line}")).color(theme::TEXT_DIM).small());
            }
        });
        ui.add_space(6.0);
    }

    fn verdict_card(&self, ui: &mut egui::Ui) {
        let d = &self.report.diagnosis;
        let color = theme::status_color(d.status);

        card(ui, color, |ui| {
            ui.label(RichText::new(&d.headline).heading().color(color));
            ui.add_space(4.0);
            let text = if self.expert && !d.expert.is_empty() {
                &d.expert
            } else {
                &d.simple
            };
            ui.label(RichText::new(text).color(theme::TEXT));

            if self.expert && !d.simple.is_empty() && !d.expert.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new(&d.simple).color(theme::TEXT_DIM).small());
            }

            if !d.actions.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("Что можно сделать").color(theme::TEXT_DIM).small());
                for action in &d.actions {
                    ui.label(format!("• {action}"));
                }
            }
        });
    }

    fn layers(&mut self, ui: &mut egui::Ui) {
        if let Some(node) = self.focus {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("Показаны проверки узла «{}»", node.title()))
                        .color(theme::TEXT_DIM),
                );
                if ui.small_button("показать все").clicked() {
                    self.focus = None;
                }
            });
            ui.add_space(4.0);
        }

        for layer in Layer::ALL {
            let checks: Vec<_> = self
                .report
                .checks_of(layer)
                .filter(|c| self.focus.is_none_or(|n| c.node == n))
                .collect();
            if checks.is_empty() {
                continue;
            }

            let rolled = checks
                .iter()
                .fold(Status::Pending, |acc, c| acc.worse(c.status));
            let color = theme::status_color(rolled);

            ui.add_space(6.0);
            ui.label(
                RichText::new(format!(
                    "{} · {} — {}",
                    layer.code(),
                    layer.title(),
                    layer.plain()
                ))
                .color(color)
                .strong(),
            );

            for check in checks {
                let head = format!("[{}] {}", check.status.glyph(), check.title);
                egui::CollapsingHeader::new(
                    RichText::new(head).color(theme::status_color(check.status)),
                )
                .id_salt(check.id)
                .show(ui, |ui| {
                    let text = if self.expert && !check.expert.is_empty() {
                        &check.expert
                    } else {
                        &check.simple
                    };
                    ui.label(text);
                    if self.expert && !check.evidence.is_empty() {
                        ui.add_space(4.0);
                        for line in &check.evidence {
                            ui.label(RichText::new(line).monospace().color(theme::TEXT_DIM));
                        }
                    }
                });
            }
        }

        if self.report.checks.is_empty() {
            ui.label(RichText::new("Проверки ещё не выполнялись.").color(theme::TEXT_DIM));
        }
    }

    fn about(&self, ui: &mut egui::Ui) {
        card(ui, theme::OUTLINE, |ui| {
            ui.label(RichText::new("Netchecker").heading());
            ui.label(
                "Программа проверяет подключение к интернету по уровням модели OSI \
                 и показывает, на каком участке пропадает связь.",
            );
            ui.add_space(8.0);
            ui.label(RichText::new(self.caps.icmp.title()).color(theme::BUSY).strong());
            ui.label(RichText::new(self.caps.icmp.explanation()).color(theme::TEXT_DIM));
            ui.label(
                RichText::new(if self.caps.elevated {
                    "Программа запущена с правами администратора."
                } else {
                    "Программа запущена без прав администратора."
                })
                .color(theme::TEXT_DIM)
                .small(),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "Сейчас доступен базовый набор проверок. Дальше появятся разбор блокировок, \
                     сравнение DNS, трассировка, мониторинг и значок в трее.",
                )
                .color(theme::TEXT_DIM),
            );
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.drain_events();
        if self.running {
            // Пока идут проверки, перерисовываем окно сами: событий от мыши
            // может не быть вовсе, а прогресс должен двигаться.
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(120));
        }

        egui::Panel::top("toolbar")
            .frame(egui::Frame::new().inner_margin(12.0).fill(theme::PANEL))
            .show(ui, |ui| self.toolbar(ui));

        if self.running {
            egui::Panel::top("progress")
                .frame(egui::Frame::new().inner_margin(egui::Margin::symmetric(12, 6)))
                .show(ui, |ui| {
                    let fraction = if self.total == 0 {
                        0.0
                    } else {
                        self.done as f32 / self.total as f32
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .text(self.progress_label.clone())
                            .fill(theme::BUSY),
                    );
                });
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(12.0).fill(theme::BG))
            .show(ui, |ui| {
                ScrollArea::vertical().show(ui, |ui| match self.tab {
                    Tab::Overview => self.overview(ui),
                    Tab::Layers => self.layers(ui),
                    Tab::About => self.about(ui),
                });
            });
    }
}

/// Карточка с цветной рамкой — единственный контейнер, который тут нужен.
fn card(ui: &mut egui::Ui, accent: Color32, body: impl FnOnce(&mut egui::Ui)) {
    let response = egui::Frame::new()
        .fill(theme::PANEL)
        .inner_margin(14.0)
        .corner_radius(CornerRadius::same(10))
        .show(ui, body);
    ui.painter().rect_stroke(
        response.response.rect,
        CornerRadius::same(10),
        Stroke::new(1.0, accent),
        StrokeKind::Inside,
    );
}
