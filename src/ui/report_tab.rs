//! Вкладка «Отчёт»: тот же разбор, но в виде текста, который можно отдать
//! человеку по ту сторону — в поддержку провайдера или знакомому сетевику.
//!
//! Поэтому здесь всегда полный текст, без деления на простой и экспертный
//! режим: получатель заранее неизвестен, а урезанный отчёт бесполезен обоим.

use eframe::egui::{self, RichText, ScrollArea};

use crate::model::Report;
use crate::privileged::Capabilities;
use crate::report;

/// Что случилось с последней попыткой сохранить отчёт.
#[derive(Default)]
pub struct SaveState {
    message: Option<String>,
    failed: bool,
}

pub fn show(ui: &mut egui::Ui, report: &Report, caps: Capabilities, state: &mut SaveState) {
    let text = report::render(report, caps);

    ui.horizontal(|ui| {
        if ui.button("Скопировать").clicked() {
            ui.ctx().copy_text(text.clone());
            state.message = Some("Отчёт скопирован в буфер обмена.".into());
            state.failed = false;
        }
        if ui.button("Сохранить в файл").clicked() {
            match save(&text) {
                Ok(path) => {
                    state.message = Some(format!("Сохранено: {path}"));
                    state.failed = false;
                }
                Err(e) => {
                    state.message = Some(format!("Не удалось сохранить: {e}"));
                    state.failed = true;
                }
            }
        }
    });

    if let Some(message) = &state.message {
        let color = if state.failed {
            super::theme::FAIL
        } else {
            super::theme::OK
        };
        ui.label(RichText::new(message).color(color).small());
    }

    ui.add_space(6.0);
    ScrollArea::both().show(ui, |ui| {
        // Моноширинный текст: в отчёте есть выровненные столбцы схемы сети,
        // пропорциональный шрифт их развалит.
        ui.add(
            egui::TextEdit::multiline(&mut text.as_str())
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .desired_rows(24),
        );
    });
}

/// Кладёт отчёт туда, где пользователь заведомо его найдёт.
///
/// Диалог выбора файла сюда не тянем: он потребовал бы системных зависимостей,
/// а единственное, что от него нужно, — предсказуемый путь. Его мы и печатаем
/// рядом с кнопкой.
fn save(text: &str) -> Result<String, String> {
    let dirs = directories::UserDirs::new().ok_or("не удалось определить домашнюю папку")?;
    let dir = dirs
        .document_dir()
        .or_else(|| dirs.download_dir())
        .or_else(|| dirs.desktop_dir())
        .unwrap_or_else(|| dirs.home_dir());

    let path = dir.join("netchecker-отчёт.txt");
    std::fs::write(&path, text).map_err(|e| e.to_string())?;
    Ok(path.display().to_string())
}
