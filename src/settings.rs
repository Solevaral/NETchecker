//! Настройки программы: что проверять и как себя вести.
//!
//! Хранятся в обычном JSON рядом с профилем пользователя, поэтому их можно
//! править и руками. Всякое отсутствующее поле подставляется по умолчанию —
//! файл, написанный прошлой версией программы, обязан читаться новой.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::targets::{self, TargetList};

/// Границы интервала мониторинга.
///
/// Чаще раза в пять секунд опрашивать бессмысленно — обрыв короче этого
/// человек всё равно не заметит, а нагрузка на канал уже заметна. Реже
/// пяти минут — мониторинг перестаёт быть мониторингом.
pub const MIN_INTERVAL: u64 = 5;
pub const MAX_INTERVAL: u64 = 300;
pub const DEFAULT_INTERVAL: u64 = 15;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Цели проверки, по одной строке.
    pub targets: Vec<String>,
    /// Как часто мониторинг опрашивает связь, в секундах.
    pub monitor_interval: u64,
    /// Включать мониторинг сразу при запуске.
    pub monitor_on_start: bool,
    /// Запускаться сразу свёрнутым в трей.
    pub start_minimized: bool,
    /// Запускаться вместе с системой. Настоящий источник правды — сама
    /// система; здесь мы храним лишь то, что просил пользователь, чтобы
    /// показать галочку до того, как опросим систему.
    pub autostart: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            targets: targets::defaults(),
            monitor_interval: DEFAULT_INTERVAL,
            monitor_on_start: false,
            start_minimized: false,
            autostart: false,
        }
    }
}

impl Settings {
    /// Читает настройки. Любая беда — отсутствие файла, испорченный JSON —
    /// означает возврат к умолчаниям: программа диагностики не имеет права
    /// не запуститься из-за своего же файла настроек.
    pub fn load() -> Self {
        let Some(path) = path() else {
            return Self::default();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        // Windows-редакторы («Блокнот», PowerShell) ставят в начало файла
        // метку кодировки. Разборщик JSON её не ждёт, и правки пользователя
        // молча пропадали бы.
        let text = text.trim_start_matches('\u{FEFF}');
        serde_json::from_str(text).unwrap_or_default()
    }

    pub fn save(&self) -> Result<PathBuf, String> {
        let path = path().ok_or("не удалось определить папку настроек")?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&path, text).map_err(|e| e.to_string())?;
        Ok(path)
    }

    pub fn target_list(&self) -> TargetList {
        let (list, _) = TargetList::from_lines(&self.targets);
        if list.is_empty() {
            TargetList::default()
        } else {
            list
        }
    }

    pub fn set_targets(&mut self, list: &TargetList) {
        self.targets = list.items().iter().map(|t| t.value.clone()).collect();
    }

    /// Интервал, приведённый к разумным границам: файл могли править руками.
    pub fn interval(&self) -> u64 {
        self.monitor_interval.clamp(MIN_INTERVAL, MAX_INTERVAL)
    }
}

pub fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "netchecker")
        .map(|dirs| dirs.config_dir().join("settings.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Файл от прошлой версии, где были только цели, обязан читаться:
    /// иначе обновление программы стирает пользователю настройки.
    #[test]
    fn file_without_new_fields_still_loads() {
        let old = r#"{ "targets": ["ya.ru"] }"#;
        let settings: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(settings.targets, vec!["ya.ru"]);
        assert_eq!(settings.monitor_interval, DEFAULT_INTERVAL);
        assert!(!settings.autostart);
    }

    #[test]
    fn settings_survive_a_round_trip() {
        let mut settings = Settings::default();
        settings.monitor_interval = 42;
        settings.start_minimized = true;
        let text = serde_json::to_string(&settings).unwrap();
        assert_eq!(serde_json::from_str::<Settings>(&text).unwrap(), settings);
    }

    /// Интервал из файла, правленного руками, не должен превращаться
    /// ни в поток запросов, ни в вечное молчание.
    #[test]
    fn interval_is_kept_within_sane_bounds() {
        let mut s = Settings::default();
        s.monitor_interval = 0;
        assert_eq!(s.interval(), MIN_INTERVAL);
        s.monitor_interval = 99_999;
        assert_eq!(s.interval(), MAX_INTERVAL);
    }

    #[test]
    fn empty_target_list_falls_back_to_defaults() {
        let mut s = Settings::default();
        s.targets = vec!["".into(), "  ".into()];
        assert!(!s.target_list().is_empty());
    }
}
