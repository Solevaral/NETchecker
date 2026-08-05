//! Netchecker — диагностика интернет-соединения по уровням модели OSI.
//!
//! Программа отвечает на вопрос «почему не работает интернет»: показывает
//! цепочку от компьютера до сайта, отмечает участок, где теряется связь,
//! и объясняет причину дважды — простыми словами и на языке сетевика.

// На Windows окно консоли рядом с GUI не нужно, но в отладочной сборке
// оно удобно для логов.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod bus;
mod engine;
mod logo;
mod model;
mod privileged;
mod ui;

use eframe::egui;

fn main() -> eframe::Result<()> {
    let icon = logo::render(256);

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Netchecker — проверка интернета")
            .with_inner_size([1040.0, 720.0])
            .with_min_inner_size([760.0, 520.0])
            .with_icon(egui::IconData {
                rgba: icon.pixels,
                width: icon.width,
                height: icon.height,
            }),
        ..Default::default()
    };

    eframe::run_native(
        "netchecker",
        options,
        Box::new(|cc| Ok(Box::new(ui::App::new(cc)))),
    )
}
