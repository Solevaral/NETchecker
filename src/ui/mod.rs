//! Интерфейс программы. Ничего сетевого здесь нет: окно только показывает
//! то, что прислал движок через шину событий.

pub mod app;
pub mod report_tab;
pub mod theme;
pub mod topology;

pub use app::App;
