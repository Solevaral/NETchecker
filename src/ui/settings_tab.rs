//! Вкладка «Настройки».

use eframe::egui::{self, RichText};

use crate::settings::{Settings, MAX_INTERVAL, MIN_INTERVAL};
use crate::tray;
use crate::ui::theme;

#[derive(Default)]
pub struct State {
    message: Option<String>,
    failed: bool,
}

/// О чём вкладка просит снаружи.
pub struct Outcome {
    /// Настройки изменились и сохранены.
    pub changed: bool,
    /// Автозапуск переключён — значку в трее надо обновить галочку.
    pub autostart_changed: bool,
}

pub fn show(
    ui: &mut egui::Ui,
    settings: &mut Settings,
    state: &mut State,
    tray_available: bool,
) -> Outcome {
    let mut changed = false;
    let mut autostart_changed = false;

    ui.label(RichText::new("Наблюдение").strong());
    changed |= ui
        .checkbox(
            &mut settings.monitor_on_start,
            "Включать наблюдение при запуске",
        )
        .changed();

    ui.horizontal(|ui| {
        ui.label("Опрашивать раз в");
        let mut seconds = settings.interval();
        if ui
            .add(egui::Slider::new(&mut seconds, MIN_INTERVAL..=MAX_INTERVAL).suffix(" с"))
            .changed()
        {
            settings.monitor_interval = seconds;
            changed = true;
        }
    });

    ui.add_space(10.0);
    ui.label(RichText::new("Запуск").strong());

    // Состояние автозапуска спрашиваем у системы, а не у файла настроек:
    // пользователь мог убрать программу из автозапуска штатными средствами,
    // и галочка обязана это показывать.
    let mut autostart = tray::autostart::is_enabled();
    if ui
        .checkbox(&mut autostart, "Запускать вместе с системой")
        .changed()
    {
        match tray::autostart::set(autostart) {
            Ok(()) => {
                settings.autostart = autostart;
                changed = true;
                autostart_changed = true;
                state.message = Some(if autostart {
                    "Программа будет запускаться вместе с системой, свёрнутой в трей.".into()
                } else {
                    "Автозапуск выключен.".into()
                });
                state.failed = false;
            }
            Err(e) => {
                state.message = Some(format!("Не удалось изменить автозапуск: {e}"));
                state.failed = true;
            }
        }
    }

    changed |= ui
        .checkbox(&mut settings.start_minimized, "Запускаться свёрнутым в трей")
        .changed();

    if !tray_available {
        ui.label(
            RichText::new(
                "Значок в трее в этой системе недоступен, поэтому окно при закрытии \
                 не прячется, а программа завершается.",
            )
            .color(theme::WARN)
            .small(),
        );
    }

    if let Some(message) = &state.message {
        ui.add_space(6.0);
        let color = if state.failed { theme::FAIL } else { theme::OK };
        ui.label(RichText::new(message).color(color).small());
    }

    ui.add_space(12.0);
    if let Some(path) = crate::settings::path() {
        ui.label(
            RichText::new(format!("Настройки хранятся в {}", path.display()))
                .color(theme::TEXT_DIM)
                .small(),
        );
    }

    Outcome {
        changed,
        autostart_changed,
    }
}
