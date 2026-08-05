//! Схема сети: цепочка узлов от компьютера до сайта.
//!
//! Это главный экран программы. Вместо списка ошибок человек видит, докуда
//! трафик доходит и на каком участке он теряется, а под каждым узлом —
//! его адрес. Иконки рисуются кодом, поэтому не тянут за собой ни файлов,
//! ни декодера картинок.

use eframe::egui::{
    self, Align2, Color32, CornerRadius, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, Vec2,
};

use crate::model::{NodeId, Report, Status};
use crate::ui::theme;

/// Рисует схему и возвращает узел, по которому кликнули.
pub fn show(ui: &mut Ui, report: &Report) -> Option<NodeId> {
    let count = report.nodes.len() as f32;
    let height = 150.0;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::hover());

    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, CornerRadius::same(10), theme::PANEL);

    let cell = rect.width() / count;
    let node_w = (cell - 16.0).clamp(70.0, 150.0);
    let node_h = 62.0;
    let center_y = rect.top() + 56.0;

    let centers: Vec<Pos2> = (0..report.nodes.len())
        .map(|i| Pos2::new(rect.left() + cell * (i as f32 + 0.5), center_y))
        .collect();

    let break_edge = report.diagnosis.break_edge;
    let mut clicked = None;

    // Сначала связи, чтобы узлы легли поверх них.
    for i in 0..report.nodes.len().saturating_sub(1) {
        let from = report.nodes[i].id;
        let to = report.nodes[i + 1].id;
        let a = Pos2::new(centers[i].x + node_w / 2.0, center_y);
        let b = Pos2::new(centers[i + 1].x - node_w / 2.0, center_y);
        let is_break = break_edge == Some((from, to));

        if is_break {
            draw_break(&painter, a, b);
        } else {
            let color = edge_color(report.nodes[i].status, report.nodes[i + 1].status);
            painter.line_segment([a, b], Stroke::new(3.0, color));
        }
    }

    for (i, node) in report.nodes.iter().enumerate() {
        let node_rect = Rect::from_center_size(centers[i], Vec2::new(node_w, node_h));
        let color = theme::status_color(node.status);

        painter.rect_filled(node_rect, CornerRadius::same(8), theme::BG);
        painter.rect_stroke(
            node_rect,
            CornerRadius::same(8),
            Stroke::new(2.0, color),
            StrokeKind::Inside,
        );

        draw_glyph(&painter, node.id, node_rect.center() - Vec2::new(0.0, 4.0), color);

        // Название и адрес — под рамкой, чтобы не тесниться внутри неё.
        painter.text(
            Pos2::new(centers[i].x, node_rect.bottom() + 8.0),
            Align2::CENTER_TOP,
            node.id.title(),
            FontId::proportional(13.0),
            theme::TEXT,
        );
        let caption = node
            .address
            .clone()
            .unwrap_or_else(|| node.subtitle.clone());
        if !caption.is_empty() {
            painter.text(
                Pos2::new(centers[i].x, node_rect.bottom() + 25.0),
                Align2::CENTER_TOP,
                ellipsize(&caption, node_w),
                FontId::monospace(11.0),
                theme::TEXT_DIM,
            );
        }

        let response = ui.interact(
            node_rect,
            ui.id().with(("topology-node", i)),
            Sense::click(),
        );
        if response.clicked() {
            clicked = Some(node.id);
        }
        if response.hovered() {
            let tip = format!("{} — {}", node.id.title(), node.status.label());
            response.on_hover_text(tip);
        }
    }

    clicked
}

/// Разрыв рисуется явно: пунктир, крест и подпись, чтобы место обрыва
/// читалось с одного взгляда и без разбора цветов.
fn draw_break(painter: &egui::Painter, a: Pos2, b: Pos2) {
    let mid = Pos2::new((a.x + b.x) / 2.0, a.y);
    let stroke = Stroke::new(3.0, theme::FAIL);

    let dash = 6.0;
    let mut x = a.x;
    while x < b.x {
        let to = (x + dash).min(b.x);
        painter.line_segment([Pos2::new(x, a.y), Pos2::new(to, a.y)], stroke);
        x += dash * 2.0;
    }

    let r = 7.0;
    painter.line_segment(
        [Pos2::new(mid.x - r, mid.y - r), Pos2::new(mid.x + r, mid.y + r)],
        Stroke::new(3.5, theme::FAIL),
    );
    painter.line_segment(
        [Pos2::new(mid.x + r, mid.y - r), Pos2::new(mid.x - r, mid.y + r)],
        Stroke::new(3.5, theme::FAIL),
    );
    painter.text(
        Pos2::new(mid.x, mid.y - 16.0),
        Align2::CENTER_BOTTOM,
        "обрыв",
        FontId::proportional(12.0),
        theme::FAIL,
    );
}

/// Цвет связи определяется худшим из двух её концов.
fn edge_color(from: Status, to: Status) -> Color32 {
    if from == Status::Ok && to == Status::Ok {
        theme::OK
    } else {
        theme::IDLE
    }
}

/// Узнаваемый значок узла. Формы намеренно разные, чтобы их можно было
/// различить и без цвета.
fn draw_glyph(painter: &egui::Painter, id: NodeId, center: Pos2, color: Color32) {
    let s = Stroke::new(2.0, color);
    match id {
        NodeId::Pc => {
            // Монитор с подставкой.
            let screen = Rect::from_center_size(center - Vec2::new(0.0, 3.0), Vec2::new(26.0, 18.0));
            painter.rect_stroke(screen, CornerRadius::same(2), s, StrokeKind::Inside);
            painter.line_segment(
                [
                    Pos2::new(center.x - 8.0, screen.bottom() + 6.0),
                    Pos2::new(center.x + 8.0, screen.bottom() + 6.0),
                ],
                s,
            );
        }
        NodeId::Router => {
            // Корпус с двумя антеннами.
            let body = Rect::from_center_size(center + Vec2::new(0.0, 5.0), Vec2::new(28.0, 12.0));
            painter.rect_stroke(body, CornerRadius::same(3), s, StrokeKind::Inside);
            painter.line_segment(
                [Pos2::new(center.x - 8.0, body.top()), Pos2::new(center.x - 12.0, body.top() - 12.0)],
                s,
            );
            painter.line_segment(
                [Pos2::new(center.x + 8.0, body.top()), Pos2::new(center.x + 12.0, body.top() - 12.0)],
                s,
            );
        }
        NodeId::Provider => {
            // Стойка серверов.
            for i in 0..3 {
                let r = Rect::from_center_size(
                    center + Vec2::new(0.0, i as f32 * 9.0 - 9.0),
                    Vec2::new(26.0, 7.0),
                );
                painter.rect_stroke(r, CornerRadius::same(1), s, StrokeKind::Inside);
            }
        }
        NodeId::Dpi => {
            // Воронка-фильтр.
            let top = 11.0;
            painter.line_segment(
                [Pos2::new(center.x - 14.0, center.y - top), Pos2::new(center.x + 14.0, center.y - top)],
                s,
            );
            painter.line_segment(
                [Pos2::new(center.x - 14.0, center.y - top), Pos2::new(center.x - 2.0, center.y + 4.0)],
                s,
            );
            painter.line_segment(
                [Pos2::new(center.x + 14.0, center.y - top), Pos2::new(center.x + 2.0, center.y + 4.0)],
                s,
            );
            painter.line_segment(
                [Pos2::new(center.x - 2.0, center.y + 4.0), Pos2::new(center.x - 2.0, center.y + 12.0)],
                s,
            );
            painter.line_segment(
                [Pos2::new(center.x + 2.0, center.y + 4.0), Pos2::new(center.x + 2.0, center.y + 12.0)],
                s,
            );
        }
        NodeId::Internet => {
            // Глобус: круг с меридианом и параллелью.
            painter.circle_stroke(center, 13.0, s);
            painter.line_segment(
                [Pos2::new(center.x - 13.0, center.y), Pos2::new(center.x + 13.0, center.y)],
                s,
            );
            painter.add(egui::Shape::closed_line(
                ellipse_points(center, 6.0, 13.0),
                s,
            ));
        }
        NodeId::Target => {
            // Флажок цели.
            painter.line_segment(
                [Pos2::new(center.x - 9.0, center.y - 13.0), Pos2::new(center.x - 9.0, center.y + 13.0)],
                s,
            );
            painter.add(egui::Shape::closed_line(
                vec![
                    Pos2::new(center.x - 9.0, center.y - 13.0),
                    Pos2::new(center.x + 11.0, center.y - 7.0),
                    Pos2::new(center.x - 9.0, center.y - 1.0),
                ],
                s,
            ));
        }
    }
}

fn ellipse_points(center: Pos2, rx: f32, ry: f32) -> Vec<Pos2> {
    (0..24)
        .map(|i| {
            let a = i as f32 / 24.0 * std::f32::consts::TAU;
            Pos2::new(center.x + rx * a.cos(), center.y + ry * a.sin())
        })
        .collect()
}

/// Грубая обрезка подписи по ширине ячейки: адреса IPv6 иначе наезжают
/// на соседние узлы.
fn ellipsize(text: &str, width: f32) -> String {
    let max_chars = (width / 6.5).floor() as usize;
    if text.chars().count() <= max_chars || max_chars < 4 {
        return text.to_string();
    }
    let head: String = text.chars().take(max_chars - 1).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_addresses_are_shortened() {
        let long = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
        let short = ellipsize(long, 100.0);
        assert!(short.chars().count() < long.chars().count());
        assert!(short.ends_with('…'));
    }

    #[test]
    fn short_text_is_left_alone() {
        assert_eq!(ellipsize("192.168.1.1", 200.0), "192.168.1.1");
    }
}
