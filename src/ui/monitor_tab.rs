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
                    Some(d) => format!("{} с", d.as_secs().max(1)),
                    None => "продолжается".to_string(),
                };
                ui.label(
                    RichText::new(format!(
                        "{} — {duration} · {}",
                        local_time(outage.started),
                        outage.reason
                    ))
                    .color(theme::FAIL),
                );
            }
        });
}

/// Время в виде «часы:минуты:секунды».
///
/// Полноценной работы с датами ради одной строки в журнале не заводим:
/// обрывы смотрят в тот же день, когда они случились.
fn local_time(at: SystemTime) -> String {
    let secs = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let day = secs % 86_400;
    format!("{:02}:{:02}:{:02} UTC", day / 3600, (day % 3600) / 60, day % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn time_is_formatted_as_clock() {
        let at = SystemTime::UNIX_EPOCH + Duration::from_secs(3661);
        assert_eq!(local_time(at), "01:01:01 UTC");
    }

    #[test]
    fn stopped_monitoring_is_visually_neutral() {
        assert_eq!(health_color(Health::Ok, false), theme::IDLE);
        assert_eq!(health_color(Health::Ok, true), theme::OK);
    }
}
