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
mod report;
mod targets;
mod ui;

use eframe::egui;

fn main() -> eframe::Result<()> {
    // Отчёт в консоль: тот же прогон, что и в окне, но результат можно
    // скопировать и отправить в поддержку. Заодно это единственный способ
    // проверить движок на машине без графики.
    if std::env::args().any(|a| a == "--report") {
        print_report();
        return Ok(());
    }

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

/// Прогоняет диагностику целиком и печатает отчёт.
fn print_report() {
    use bus::EngineEvent;
    use privileged::Capabilities;

    let caps = Capabilities::detect();
    let (tx, rx) = std::sync::mpsc::channel();
    // Тот же список целей, что и в окне: он лежит в настройках, а не в коде.
    engine::spawn(caps, targets::TargetList::load(), bus::Reporter::new(tx));

    let mut report = model::Report::new();
    // Канал закроется сам, когда фоновый поток завершится, — это и есть
    // признак того, что диагностика доработала.
    for event in rx {
        match event {
            EngineEvent::Check(result) => report.apply(*result),
            EngineEvent::Node {
                id,
                subtitle,
                address,
            } => {
                let node = report.node_mut(id);
                node.subtitle = subtitle;
                if address.is_some() {
                    node.address = address;
                }
            }
            EngineEvent::Finished(diagnosis) => report.diagnosis = *diagnosis,
            EngineEvent::Started { .. } | EngineEvent::Progress { .. } => {}
        }
    }

    print!("{}", report::render(&report, caps));
}
