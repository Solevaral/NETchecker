//! Вкладка «Наблюдение»: график задержек и журнал обрывов.
//!
//! График здесь не украшение: по одному числу «сейчас 20 мс» нельзя понять,
//! стабилен ли канал. Форма линии показывает то, ради чего наблюдение и
//! ведётся, — регулярные провалы, ступеньки, рост под нагрузкой.

use std::time::SystemTime;

use eframe::egui::{
    self, Align2, CornerRadius, FontId, Pos2, RichText, ScrollArea, Sense, Stroke, Vec2,
};

use crate::monitor::{Health, Snapshot};
use crate::ui::theme;

pub fn show(ui: &mut egui::Ui, snapshot: &Snapshot, running: bool, interval: u64) -> bool {
    let mut toggle = false;

    ui.horizontal(|ui| {
        let label = if running {
            "Выключить наблюдение"
        } else {
            "Включить наблюдение"
        };
        if ui.button(label).clicked() {
            toggle = true;
        }

        let color = health_color(snapshot.health, running);
        ui.label(RichText::new(snapshot.health.title()).color(color).strong());
        if running {
            ui.label(
                RichText::new(format!("опрос раз в {interval} с"))
                    .color(theme::TEXT_DIM)
                    .small(),
            );
        }
    });

    if !snapshot.summary.is_empty() {
        ui.label(RichText::new(&snapshot.summary).color(theme::TEXT_DIM).small());
    }

    ui.add_space(8.0);
    chart(ui, snapshot);

    ui.add_space(12.0);
    ui.label(RichText::new("Журнал обрывов").strong());
    journal(ui, snapshot);

    toggle
}

fn health_color(health: Health, running: bool) -> egui::Color32 {
    if !running {
        return theme::IDLE;
    }
    match health {
        Health::Ok => theme::OK,
        Health::Degraded => theme::WARN,
        Health::Down => theme::FAIL,
        Health::Unknown => theme::BUSY,
    }
}

/// Линия задержек. Потери рисуются столбиками во всю высоту — на линии их
/// было бы не видно, а именно они и есть то, что ищут.
fn chart(ui: &mut egui::Ui, snapshot: &Snapshot) {
    let height = 180.0;
    let (rect, _) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(8), theme::PANEL);

    if snapshot.samples.is_empty() {
        painter.text(
            rect.center(),
            Align2::CENTER_CENTER,
            "Наблюдение ещё не собрало замеров",
            FontId::proportional(13.0),
            theme::TEXT_DIM,
        );
        return;
    }

    let plot = rect.shrink2(Vec2::new(48.0, 12.0));
    let worst = snapshot
        .samples
        .iter()
        .filter_map(|s| s.rtt)
        .max()
        .map(|d| d.as_secs_f32() * 1000.0)
        .unwrap_or(1.0)
        .max(1.0);

    // Шкала подписывается по верхней границе: без числа график ничего
    // не говорит, кроме «бывает по-разному».
    for (fraction, label) in [(0.0, worst), (0.5, worst / 2.0), (1.0, 0.0)] {
        let y = plot.top() + plot.height() * fraction;
        painter.line_segment(
            [Pos2::new(plot.left(), y), Pos2::new(plot.right(), y)],
            Stroke::new(1.0, theme::OUTLINE),
        );
        painter.text(
            Pos2::new(plot.left() - 6.0, y),
            Align2::RIGHT_CENTER,
            format!("{label:.0} мс"),
            FontId::monospace(10.0),
            theme::TEXT_DIM,
        );
    }

    let count = snapshot.samples.len();
    let step = plot.width() / count.max(2) as f32;
    let mut line: Vec<Pos2> = Vec::with_capacity(count);

    for (i, sample) in snapshot.samples.iter().enumerate() {
        let x = plot.left() + step * i as f32;
        match sample.rtt {
            Some(rtt) => {
                let value = rtt.as_secs_f32() * 1000.0;
                let y = plot.bottom() - plot.height() * (value / worst);
                line.push(Pos2::new(x, y));
            }
            None => {
                // Разрыв в линии плюс столбик: потеря должна быть заметна
                // и по форме, и по цвету.
                if line.len() > 1 {
                    painter.add(egui::Shape::line(
                        std::mem::take(&mut line),
                        Stroke::new(1.5, theme::OK),
                    ));
                } else {
                    line.clear();
                }
                painter.line_segment(
                    [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom())],
                    Stroke::new(step.max(2.0).min(6.0), theme::FAIL.gamma_multiply(0.5)),
                );
            }
        }
    }
    if line.len() > 1 {
        painter.add(egui::Shape::line(line, Stroke::new(1.5, theme::OK)));
    }
}

fn journal(ui: &mut egui::Ui, snapshot: &Snapshot) {
    if snapshot.outages.is_empty() {
        ui.label(
            RichText::new("Обрывов не было.")
                .color(theme::TEXT_DIM)
                .small(),
        );
        return;
    }

    ScrollArea::vertical()
        .id_salt("outage-journal")
        .max_height(180.0)
        .show(ui, |ui| {
            // Свежие сверху: спрашивают всегда про последний обрыв.
            for outage in snapshot.outages.iter().rev() {
                let duration = match outage.duration() {
                    Some(d) => format!("длился {}", human_duration(d)),
                    None => "продолжается".to_string(),
                };
                ui.label(
                    RichText::new(format!(
                        "{} — {duration} · {}",
                        ago(outage.started),
                        outage.reason
                    ))
                    .color(theme::FAIL),
                );
            }
        });
}

/// «Сколько времени назад это случилось».
///
/// Часовой пояс без сторонней библиотеки не определить, а показывать журнал
/// обрывов по UTC — значит заставлять человека пересчитывать время в уме.
/// К тому же на вопрос «когда пропадало» относительное время отвечает прямее:
/// важно, было это пять минут назад или три часа назад, а не точный час.
fn ago(at: SystemTime) -> String {
    match SystemTime::now().duration_since(at) {
        Ok(elapsed) if elapsed.as_secs() < 10 => "только что".to_string(),
        Ok(elapsed) => format!("{} назад", human_duration(elapsed)),
        // Часы могли перевести назад — не повод показывать бессмыслицу.
        Err(_) => "только что".to_string(),
    }
}

/// Длительность словами: секунды, минуты или часы, но не всё сразу.
fn human_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=59 => format!("{} с", secs.max(1)),
        60..=3599 => format!("{} мин", secs / 60),
        _ => format!("{} ч {} мин", secs / 3600, (secs % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn durations_are_written_in_words() {
        assert_eq!(human_duration(Duration::from_millis(300)), "1 с");
        assert_eq!(human_duration(Duration::from_secs(45)), "45 с");
        assert_eq!(human_duration(Duration::from_secs(600)), "10 мин");
        assert_eq!(human_duration(Duration::from_secs(7_320)), "2 ч 2 мин");
    }

    #[test]
    fn recent_events_are_called_just_now() {
        assert_eq!(ago(SystemTime::now()), "только что");
        let long_ago = SystemTime::now() - Duration::from_secs(600);
        assert_eq!(ago(long_ago), "10 мин назад");
    }

    /// Перевод часов назад не должен превращать журнал в бессмыслицу.
    #[test]
    fn future_timestamps_do_not_break_the_journal() {
        let future = SystemTime::now() + Duration::from_secs(3600);
        assert_eq!(ago(future), "только что");
    }

    #[test]
    fn stopped_monitoring_is_visually_neutral() {
        assert_eq!(health_color(Health::Ok, false), theme::IDLE);
        assert_eq!(health_color(Health::Ok, true), theme::OK);
    }
}
