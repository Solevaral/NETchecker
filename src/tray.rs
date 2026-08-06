//! Значок в трее и автозапуск.
//!
//! Программа полезна ровно в тот момент, когда связь пропала, — а в этот
//! момент её никто не запускает: люди перезагружают роутер. Поэтому она
//! должна уже работать, тихо и не занимая место на панели задач.
//!
//! Отсюда три вещи: закрытие окна прячет его в трей вместо выхода, цвет
//! значка показывает состояние связи, а автозапуск поднимает программу
//! вместе с системой.

use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::logo;
use crate::monitor::Health;

/// Что пользователь выбрал в меню.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Open,
    CheckNow,
    ToggleMonitor,
    ToggleAutostart,
    Quit,
}

/// Цвет значка по состоянию связи.
///
/// Цвет — не единственный носитель смысла: рядом всегда есть подсказка
/// текстом, иначе значок был бы бесполезен тем, кто не различает цвета.
fn tint(health: Health, monitoring: bool) -> [u8; 3] {
    if !monitoring {
        return [0x8A, 0x93, 0xA6]; // серый: наблюдение выключено
    }
    match health {
        Health::Ok => [0x3D, 0xDC, 0x97],
        Health::Degraded => [0xF5, 0xC0, 0x42],
        Health::Down => [0xF2, 0x62, 0x5F],
        Health::Unknown => [0x58, 0xA6, 0xFF],
    }
}

/// Значок вместе со своим меню.
pub struct Tray {
    icon: TrayIcon,
    monitor_item: CheckMenuItem,
    autostart_item: CheckMenuItem,
    open_id: String,
    check_id: String,
    monitor_id: String,
    autostart_id: String,
    quit_id: String,
    /// Последнее нарисованное состояние: перерисовывать значок каждый кадр
    /// незачем, а моргание в трее заметно.
    drawn: Option<([u8; 3], String)>,
}

impl Tray {
    pub fn new(monitoring: bool, autostart: bool) -> Result<Self, String> {
        let open = MenuItem::new("Открыть Netchecker", true, None);
        let check = MenuItem::new("Проверить сейчас", true, None);
        let monitor = CheckMenuItem::new("Наблюдение за связью", true, monitoring, None);
        let autostart_item = CheckMenuItem::new("Запускать с системой", true, autostart, None);
        let quit = MenuItem::new("Выход", true, None);

        let menu = Menu::new();
        menu.append_items(&[
            &open,
            &check,
            &PredefinedMenuItem::separator(),
            &monitor,
            &autostart_item,
            &PredefinedMenuItem::separator(),
            &quit,
        ])
        .map_err(|e| e.to_string())?;

        let ids = (
            open.id().0.clone(),
            check.id().0.clone(),
            monitor.id().0.clone(),
            autostart_item.id().0.clone(),
            quit.id().0.clone(),
        );

        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("Netchecker")
            .with_icon(make_icon(tint(Health::Unknown, monitoring))?)
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            icon,
            monitor_item: monitor,
            autostart_item,
            open_id: ids.0,
            check_id: ids.1,
            monitor_id: ids.2,
            autostart_id: ids.3,
            quit_id: ids.4,
            drawn: None,
        })
    }

    /// Приводит значок в соответствие состоянию. Вызывается каждый кадр,
    /// но реально что-то делает только при изменении.
    pub fn update(&mut self, health: Health, monitoring: bool, summary: &str) {
        self.monitor_item.set_checked(monitoring);

        let colour = tint(health, monitoring);
        let tooltip = if monitoring {
            format!("Netchecker — {}\n{summary}", health.title())
        } else {
            "Netchecker — наблюдение выключено".to_string()
        };

        if self.drawn.as_ref() == Some(&(colour, tooltip.clone())) {
            return;
        }
        if let Ok(icon) = make_icon(colour) {
            let _ = self.icon.set_icon(Some(icon));
        }
        let _ = self.icon.set_tooltip(Some(&tooltip));
        self.drawn = Some((colour, tooltip));
    }

    pub fn set_autostart_checked(&self, on: bool) {
        self.autostart_item.set_checked(on);
    }

    /// Разбирает накопившиеся события меню и щелчки по значку.
    pub fn poll(&self) -> Vec<Command> {
        let mut commands = Vec::new();

        while let Ok(event) = MenuEvent::receiver().try_recv() {
            let id = &event.id().0;
            if id == &self.open_id {
                commands.push(Command::Open);
            } else if id == &self.check_id {
                commands.push(Command::CheckNow);
            } else if id == &self.monitor_id {
                commands.push(Command::ToggleMonitor);
            } else if id == &self.autostart_id {
                commands.push(Command::ToggleAutostart);
            } else if id == &self.quit_id {
                commands.push(Command::Quit);
            }
        }

        // Двойной щелчок по значку — привычный способ вернуть окно.
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::DoubleClick { .. } = event {
                commands.push(Command::Open);
            }
        }

        commands
    }
}

fn make_icon(colour: [u8; 3]) -> Result<Icon, String> {
    let image = logo::render_tinted(32, colour);
    Icon::from_rgba(image.pixels, image.width, image.height).map_err(|e| e.to_string())
}

/// Автозапуск вместе с системой.
///
/// Источник правды — сама система, а не файл настроек: пользователь мог
/// убрать программу из автозапуска штатными средствами, и галочка обязана
/// это показать.
pub mod autostart {
    use auto_launch::AutoLaunchBuilder;

    fn handle() -> Result<auto_launch::AutoLaunch, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        AutoLaunchBuilder::new()
            .set_app_name("Netchecker")
            .set_app_path(&exe.to_string_lossy())
            // Программа поднимается вместе с системой, чтобы уже наблюдать
            // за связью, а не чтобы мозолить глаза окном.
            .set_args(&["--minimized"])
            .build()
            .map_err(|e| e.to_string())
    }

    pub fn is_enabled() -> bool {
        handle().and_then(|h| h.is_enabled().map_err(|e| e.to_string())).unwrap_or(false)
    }

    pub fn set(enabled: bool) -> Result<(), String> {
        let h = handle()?;
        if enabled {
            h.enable().map_err(|e| e.to_string())
        } else {
            h.disable().map_err(|e| e.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Выключенное наблюдение обязано выглядеть иначе, чем работающее:
    /// иначе серый значок «всё тихо» не отличить от зелёного «всё хорошо».
    #[test]
    fn colours_tell_the_states_apart() {
        let off = tint(Health::Ok, false);
        let ok = tint(Health::Ok, true);
        let degraded = tint(Health::Degraded, true);
        let down = tint(Health::Down, true);

        assert_ne!(off, ok);
        assert_ne!(ok, degraded);
        assert_ne!(degraded, down);
        assert_ne!(ok, down);
    }

    #[test]
    fn icon_is_built_for_every_state() {
        for health in [Health::Unknown, Health::Ok, Health::Degraded, Health::Down] {
            assert!(make_icon(tint(health, true)).is_ok());
        }
    }
}
