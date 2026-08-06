//! Окно программы: панель управления, схема сети, вердикт и разбор по слоям.

use std::sync::mpsc::{self, TryRecvError};

use eframe::egui::{self, Color32, CornerRadius, RichText, ScrollArea, Stroke, StrokeKind};

use crate::bus::{Cancel, EngineEvent, EventRx, EventTx, Reporter};
use crate::engine;
use crate::model::{Diagnosis, Layer, NodeId, Report, Status};
use crate::monitor::Monitor;
use crate::privileged::Capabilities;
use crate::settings::Settings;
use crate::targets::TargetList;
use crate::tray::{self, Tray};
use crate::ui::{monitor_tab, report_tab, settings_tab, targets_tab, theme, topology};

/// Какой из разделов открыт.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Tab {
    Overview,
    Layers,
    Targets,
    Monitor,
    Report,
    Settings,
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
    save_state: report_tab::SaveState,
    settings: Settings,
    settings_state: settings_tab::State,
    /// Что проверять. Берётся из настроек и правится на вкладке «Цели».
    targets: TargetList,
    targets_editor: targets_tab::Editor,
    monitor: Monitor,
    /// Значок в трее. Может отсутствовать: в части окружений Linux трея нет,
    /// и это не повод не запускаться.
    tray: Option<Tray>,
    /// Окно спрятано в трей, а не закрыто.
    hidden: bool,
    /// Пользователь выбрал выход — только тогда закрываемся по-настоящему.
    quitting: bool,
    /// Признак остановки для идущей проверки.
    cancel: Cancel,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);
        let (tx, rx) = mpsc::channel();
        let caps = Capabilities::detect();
        let settings = Settings::load();
        let targets = settings.target_list();
        let monitor = Monitor::new(caps, settings.interval());

        let tray = match Tray::new(settings.monitor_on_start, tray::autostart::is_enabled()) {
            Ok(tray) => Some(tray),
            // Без трея программа остаётся обычным окном. Сообщать об этом
            // всплывающей ошибкой не за что: пользователь ничего не сделал
            // не так, а диагностика от этого не страдает.
            Err(_) => None,
        };

        if settings.monitor_on_start {
            monitor.start();
        }

        // Свёрнутый запуск нужен автозапуску: программа поднимается вместе
        // с системой, чтобы уже наблюдать за связью, а не мозолить глаза.
        let hidden = tray.is_some()
            && (settings.start_minimized || std::env::args().any(|a| a == "--minimized"));
        if hidden {
            cc.egui_ctx
                .send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        let mut app = Self {
            targets_editor: targets_tab::Editor::new(&targets),
            targets,
            settings,
            settings_state: settings_tab::State::default(),
            monitor,
            tray,
            hidden,
            quitting: false,
            cancel: Cancel::new(),
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
            save_state: report_tab::SaveState::default(),
        };
        // Первую проверку запускаем сразу: человек открыл программу именно
        // затем, чтобы узнать, что со связью.
        app.start();
        app
    }

    /// Показать окно после сворачивания в трей.
    fn reveal(&mut self, ctx: &egui::Context) {
        self.hidden = false;
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }

    /// Команды из меню значка в трее.
    fn handle_tray(&mut self, ctx: &egui::Context) {
        let Some(commands) = self.tray.as_ref().map(|t| t.poll()) else {
            return;
        };

        for command in commands {
            match command {
                tray::Command::Open => self.reveal(ctx),
                tray::Command::CheckNow => {
                    self.reveal(ctx);
                    self.start();
                }
                tray::Command::ToggleMonitor => self.toggle_monitor(),
                tray::Command::ToggleAutostart => {
                    let next = !tray::autostart::is_enabled();
                    if tray::autostart::set(next).is_ok() {
                        self.settings.autostart = next;
                        let _ = self.settings.save();
                    }
                    // Галочку в меню выставляем по факту, а не по намерению:
                    // система могла операцию и не пустить.
                    if let Some(tray) = &self.tray {
                        tray.set_autostart_checked(tray::autostart::is_enabled());
                    }
                }
                tray::Command::Quit => {
                    self.quitting = true;
                    self.monitor.stop();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
    }

    fn toggle_monitor(&mut self) {
        if self.monitor.is_running() {
            self.monitor.stop();
        } else {
            self.monitor.set_interval(self.settings.interval());
            self.monitor.start();
        }
    }

    /// Закрытие окна прячет программу в трей вместо выхода — так же, как
    /// это делают мессенджеры. Наблюдение при этом продолжает работать,
    /// иначе прятать было бы незачем.
    fn handle_close(&mut self, ctx: &egui::Context) {
        if !ctx.input(|i| i.viewport().close_requested()) {
            return;
        }
        if self.quitting || self.tray.is_none() {
            self.monitor.stop();
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        self.hidden = true;
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
        // Новый признак остановки на каждый запуск: старый мог остаться
        // взведённым от прерванной проверки.
        self.cancel = Cancel::new();
        engine::spawn(
            self.caps,
            self.targets.clone(),
            Reporter::new(self.tx.clone(), self.cancel.clone()),
        );
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
                Ok(EngineEvent::Cancelled) => {
                    self.running = false;
                    // Показываем ровно то, что успели узнать, и честно
                    // говорим, что картина неполная.
                    self.report.diagnosis = Diagnosis {
                        headline: "Проверка остановлена".into(),
                        simple: "Успевшие пройти проверки показаны ниже, остальные не \
                                 выполнялись — картина неполная."
                            .into(),
                        expert: String::new(),
                        actions: vec!["Нажмите «Проверить», чтобы пройти всё заново.".into()],
                        break_edge: None,
                        status: Status::Skipped,
                    };
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
                // Полная проверка идёт десятки секунд, и всё это время
                // человек не должен оставаться заложником запущенного
                // конвейера — поэтому кнопка меняется на «Остановить».
                if self.running {
                    if ui.button("Остановить").clicked() {
                        self.cancel.request();
                        self.progress_label = "Останавливаю…".to_string();
                    }
                } else if ui.button("Проверить").clicked() {
                    self.start();
                }
                ui.checkbox(&mut self.expert, "Экспертный режим");
            });
        });

        ui.horizontal(|ui| {
            for (tab, name) in [
                (Tab::Overview, "Схема и вывод"),
                (Tab::Layers, "Уровни OSI"),
                (Tab::Targets, "Цели"),
                (Tab::Monitor, "Наблюдение"),
                (Tab::Report, "Отчёт"),
                (Tab::Settings, "Настройки"),
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
                .id_salt(&check.id)
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
                RichText::new(if self.tray.is_some() {
                    "Закрытие окна прячет программу в значок рядом с часами — наблюдение \
                     при этом продолжает работать. Выйти совсем можно через меню значка."
                } else {
                    "Значок в трее в этой системе недоступен, поэтому закрытие окна \
                     завершает программу."
                })
                .color(theme::TEXT_DIM),
            );
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_tray(&ctx);
        self.handle_close(&ctx);

        // Значок в трее — единственное, что видно, когда окно спрятано,
        // поэтому его состояние обновляется всегда.
        if self.tray.is_some() {
            let snapshot = self.monitor.snapshot();
            let running = self.monitor.is_running();
            if let Some(tray) = &mut self.tray {
                tray.update(snapshot.health, running, &snapshot.summary);
            }
        }

        // Пока окно спрятано, egui перестаёт получать события ввода, а
        // наблюдение и меню в трее должны продолжать работать.
        if self.hidden || self.monitor.is_running() {
            ctx.request_repaint_after(std::time::Duration::from_millis(400));
        }

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
                match self.tab {
                    // У этих вкладок своя прокрутка, внешняя им мешает.
                    Tab::Report => {
                        report_tab::show(ui, &self.report, self.caps, &mut self.save_state)
                    }
                    Tab::Targets => {
                        let action = targets_tab::show(
                            ui,
                            &mut self.targets_editor,
                            &self.report,
                            self.running,
                        );
                        if let targets_tab::Action::Apply(list) = action {
                            self.settings.set_targets(&list);
                            let _ = self.settings.save();
                            self.targets = list;
                            self.tab = Tab::Overview;
                            self.start();
                        }
                    }
                    Tab::Monitor => {
                        let snapshot = self.monitor.snapshot();
                        let toggle = monitor_tab::show(
                            ui,
                            &snapshot,
                            self.monitor.is_running(),
                            self.settings.interval(),
                        );
                        if toggle {
                            self.toggle_monitor();
                        }
                    }
                    Tab::Settings => {
                        let outcome = settings_tab::show(
                            ui,
                            &mut self.settings,
                            &mut self.settings_state,
                            self.tray.is_some(),
                        );
                        if outcome.changed {
                            self.monitor.set_interval(self.settings.interval());
                            let _ = self.settings.save();
                        }
                        if outcome.autostart_changed {
                            if let Some(tray) = &self.tray {
                                tray.set_autostart_checked(tray::autostart::is_enabled());
                            }
                        }
                    }
                    _ => {
                        ScrollArea::vertical().show(ui, |ui| match self.tab {
                            Tab::Overview => self.overview(ui),
                            Tab::Layers => self.layers(ui),
                            Tab::About => self.about(ui),
                            Tab::Report | Tab::Targets | Tab::Monitor | Tab::Settings => {
                                unreachable!("обработаны выше")
                            }
                        });
                    }
                }
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
