//! Цвета и мелкие визуальные соглашения, общие для всех частей окна.

use eframe::egui::Color32;

use crate::model::Status;

pub const BG: Color32 = Color32::from_rgb(0x10, 0x14, 0x1F);
pub const PANEL: Color32 = Color32::from_rgb(0x18, 0x1F, 0x30);
pub const OUTLINE: Color32 = Color32::from_rgb(0x2A, 0x35, 0x4D);
pub const TEXT: Color32 = Color32::from_rgb(0xE6, 0xEA, 0xF2);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x93, 0x9F, 0xB8);

pub const OK: Color32 = Color32::from_rgb(0x3D, 0xDC, 0x97);
pub const WARN: Color32 = Color32::from_rgb(0xF5, 0xC0, 0x42);
pub const FAIL: Color32 = Color32::from_rgb(0xF2, 0x62, 0x5F);
pub const BUSY: Color32 = Color32::from_rgb(0x58, 0xA6, 0xFF);
pub const IDLE: Color32 = Color32::from_rgb(0x5A, 0x66, 0x7E);

pub fn status_color(status: Status) -> Color32 {
    match status {
        Status::Ok => OK,
        Status::Warn => WARN,
        Status::Fail => FAIL,
        Status::Running => BUSY,
        Status::Pending | Status::Skipped => IDLE,
    }
}

/// Тёмная тема окна. Задаётся один раз при старте.
///
/// Тема принудительно тёмная в обоих наборах стилей: схема сети опирается на
/// цветовые акценты, подобранные под тёмный фон, и на светлом они теряются.
pub fn apply(ctx: &eframe::egui::Context) {
    use eframe::egui::{FontFamily, FontId, TextStyle, ThemePreference};

    ctx.set_theme(ThemePreference::Dark);
    ctx.all_styles_mut(|style| {
        style.visuals.dark_mode = true;
        style.visuals.panel_fill = BG;
        style.visuals.window_fill = PANEL;
        style.visuals.extreme_bg_color = BG;
        style.visuals.override_text_color = Some(TEXT);
        style.spacing.item_spacing = eframe::egui::vec2(8.0, 8.0);
        style.spacing.button_padding = eframe::egui::vec2(12.0, 6.0);

        style.text_styles = [
            (TextStyle::Heading, FontId::new(22.0, FontFamily::Proportional)),
            (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)),
            (TextStyle::Button, FontId::new(14.5, FontFamily::Proportional)),
            (TextStyle::Small, FontId::new(12.0, FontFamily::Proportional)),
            (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
        ]
        .into();
    });
}
