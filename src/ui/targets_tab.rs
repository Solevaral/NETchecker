//! Вкладка «Цели»: что именно проверять.
//!
//! Список правится прямо здесь и построчно — так его удобнее всего вставлять
//! целиком из письма или заметки. Рядом таблица с последним результатом по
//! каждой цели и поиск: когда целей несколько десятков, важно сразу видеть
//! проблемные, а не листать список глазами.

use eframe::egui::{self, RichText, ScrollArea};

use crate::model::{Report, Status};
use crate::targets::{TargetList, MAX};
use crate::ui::theme;

/// Состояние редактора между кадрами.
pub struct Editor {
    /// Текст поля ввода. Живёт отдельно от разобранного списка: пока человек
    /// печатает, промежуточные строки не должны ничего ломать.
    text: String,
    search: String,
    message: Option<String>,
    failed: bool,
    /// Строки, которые не удалось понять при последнем применении.
    rejected: Vec<String>,
}

impl Editor {
    pub fn new(list: &TargetList) -> Self {
        Self {
            text: list.to_text(),
            search: String::new(),
            message: None,
            failed: false,
            rejected: Vec::new(),
        }
    }
}

/// Что вкладка просит сделать снаружи.
pub enum Action {
    None,
    /// Список изменён — применить и перепроверить.
    Apply(TargetList),
}

pub fn show(ui: &mut egui::Ui, editor: &mut Editor, report: &Report, busy: bool) -> Action {
    let mut action = Action::None;

    ui.label(
        RichText::new(
            "Сюда можно вставить список сразу целиком — по одному домену или адресу \
             на строку. Строки, начинающиеся с #, пропускаются.",
        )
        .color(theme::TEXT_DIM),
    );
    ui.add_space(6.0);

    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width((ui.available_width() * 0.45).max(240.0));
            ScrollArea::vertical()
                .id_salt("targets-editor")
                .max_height(320.0)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut editor.text)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(14)
                            .hint_text("example.com\n1.1.1.1\nwww.youtube.com"),
                    );
                });

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(!busy, egui::Button::new("Применить и проверить"))
                    .clicked()
                {
                    let (list, rejected) = TargetList::parse(&editor.text);
                    editor.rejected = rejected;

                    if list.is_empty() {
                        editor.message = Some("Список пуст — проверять нечего.".into());
                        editor.failed = true;
                    } else {
                        // Нормализованный текст возвращается в поле: человек
                        // должен видеть, что именно программа приняла.
                        editor.text = list.to_text();
                        match list.save() {
                            Ok(path) => {
                                editor.message =
                                    Some(format!("Сохранено: {}", path.display()));
                                editor.failed = false;
                            }
                            Err(e) => {
                                editor.message =
                                    Some(format!("Список принят, но не сохранён: {e}"));
                                editor.failed = true;
                            }
                        }
                        action = Action::Apply(list);
                    }
                }

                if ui.button("Вернуть стандартный список").clicked() {
                    editor.text = TargetList::default().to_text();
                    editor.rejected.clear();
                    editor.message = Some("Список возвращён к стандартному. Нажмите «Применить».".into());
                    editor.failed = false;
                }
            });

            if let Some(message) = &editor.message {
                let color = if editor.failed { theme::WARN } else { theme::OK };
                ui.label(RichText::new(message).color(color).small());
            }

            // Непонятые строки нельзя выбрасывать молча: человек должен
            // увидеть, что именно программа не приняла, и поправить.
            if !editor.rejected.is_empty() {
                ui.add_space(4.0);
                ui.label(
                    RichText::new("Эти строки не приняты — непохоже ни на домен, ни на адрес:")
                        .color(theme::FAIL)
                        .small(),
                );
                for line in &editor.rejected {
                    ui.label(RichText::new(format!("• {line}")).color(theme::FAIL).small());
                }
            }

            ui.add_space(4.0);
            let count = TargetList::parse(&editor.text).0.items().len();
            ui.label(
                RichText::new(format!("Целей в списке: {count} (не больше {MAX})"))
                    .color(theme::TEXT_DIM)
                    .small(),
            );
        });

        ui.separator();

        ui.vertical(|ui| {
            ui.horizontal(|ui| {
                ui.label("Поиск:");
                ui.add(
                    egui::TextEdit::singleline(&mut editor.search)
                        .hint_text("часть имени или адреса")
                        .desired_width(200.0),
                );
                if !editor.search.is_empty() && ui.small_button("сбросить").clicked() {
                    editor.search.clear();
                }
            });
            ui.add_space(4.0);
            results_table(ui, editor, report);
        });
    });

    action
}

/// Таблица с последним результатом по каждой цели.
fn results_table(ui: &mut egui::Ui, editor: &Editor, report: &Report) {
    let (list, _) = TargetList::parse(&editor.text);
    let needle = editor.search.trim().to_lowercase();

    ScrollArea::vertical()
        .id_salt("targets-results")
        .max_height(360.0)
        .show(ui, |ui| {
            egui::Grid::new("targets-grid")
                .num_columns(3)
                .striped(true)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Цель").color(theme::TEXT_DIM).small());
                    ui.label(RichText::new("Тип").color(theme::TEXT_DIM).small());
                    ui.label(RichText::new("Результат").color(theme::TEXT_DIM).small());
                    ui.end_row();

                    let mut shown = 0;
                    for target in list.items() {
                        if !needle.is_empty() && !target.value.to_lowercase().contains(&needle) {
                            continue;
                        }
                        shown += 1;

                        // Результат ищем по идентификатору проверки, который
                        // движок заводит для каждой цели.
                        let check = report
                            .checks
                            .iter()
                            .find(|c| c.id == format!("l7.target.{}", target.value));

                        let (status, verdict) = match check {
                            Some(c) => (
                                c.status,
                                c.title
                                    .rsplit(" — ")
                                    .next()
                                    .unwrap_or("проверено")
                                    .to_string(),
                            ),
                            None => (Status::Pending, "ещё не проверялось".to_string()),
                        };

                        ui.label(RichText::new(&target.value).monospace());
                        ui.label(
                            RichText::new(target.kind.title())
                                .color(theme::TEXT_DIM)
                                .small(),
                        );
                        ui.label(
                            RichText::new(format!("[{}] {verdict}", status.glyph()))
                                .color(theme::status_color(status)),
                        );
                        ui.end_row();
                    }

                    if shown == 0 {
                        ui.label(
                            RichText::new("Ничего не найдено")
                                .color(theme::TEXT_DIM)
                                .small(),
                        );
                        ui.end_row();
                    }
                });
        });
}
