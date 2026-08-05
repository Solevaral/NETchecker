//! Логотип программы, нарисованный кодом.
//!
//! Иконка нужна в нескольких видах: окно, exe, трей — причём в трее её цвет
//! меняется в зависимости от состояния мониторинга. Держать полдюжины готовых
//! PNG под каждый цвет неудобно, поэтому логотип рисуется процедурно в любой
//! размер и любой цвет. Заодно это избавляет от декодера изображений в
//! зависимостях.
//!
//! Рисунок: три узла сети, соединённые линиями, и проходящая сквозь них линия
//! пульса — «проверка связи». Мастер-эскиз лежит в `assets/logo.svg`,
//! геометрия ниже повторяет его один в один в системе координат 256×256.

/// Готовое изображение в формате RGBA8, как его ждут egui и tray-icon.
pub struct Rgba {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

const CANVAS: f32 = 256.0;

const BG: [u8; 3] = [0x10, 0x1B, 0x33];
const LINK: [u8; 3] = [0x2F, 0x5F, 0xB5];
const NODE: [u8; 3] = [0x58, 0xA6, 0xFF];
const PULSE: [u8; 3] = [0x3D, 0xDC, 0x97];

/// Узлы сети в координатах эскиза.
const NODES: [(f32, f32); 3] = [(40.0, 150.0), (216.0, 150.0), (128.0, 66.0)];
const NODE_R: f32 = 15.0;
const LINK_W: f32 = 8.0;

/// Ломаная линии пульса.
const PULSE_PATH: [(f32, f32); 7] = [
    (40.0, 150.0),
    (80.0, 150.0),
    (100.0, 112.0),
    (126.0, 192.0),
    (150.0, 132.0),
    (170.0, 150.0),
    (216.0, 150.0),
];
const PULSE_W: f32 = 15.0;

/// Полный логотип с тёмной подложкой — для окна и exe.
pub fn render(size: u32) -> Rgba {
    draw(size, Some(BG), LINK, NODE, PULSE)
}

/// Силуэт одним цветом на прозрачном фоне — для иконки в трее.
///
/// Трей перекрашивает иконку под текущее состояние мониторинга, поэтому
/// подложка здесь не нужна, а все элементы рисуются одним `tint`.
// Значок в трее появится вместе с режимом мониторинга; функция готова заранее
// и покрыта тестами, чтобы форма логотипа менялась в одном месте.
#[allow(dead_code)]
pub fn render_tinted(size: u32, tint: [u8; 3]) -> Rgba {
    draw(size, None, tint, tint, tint)
}

fn draw(size: u32, bg: Option<[u8; 3]>, link: [u8; 3], node: [u8; 3], pulse: [u8; 3]) -> Rgba {
    let scale = CANVAS / size as f32;
    let mut pixels = vec![0u8; (size * size * 4) as usize];

    for y in 0..size {
        for x in 0..size {
            // Сглаживание сеткой 3×3 подпикселей: дешевле полноценного
            // растеризатора и на 16 px уже неотличимо.
            let mut acc = [0.0f32; 4];
            for sy in 0..3 {
                for sx in 0..3 {
                    let px = (x as f32 + (sx as f32 + 0.5) / 3.0) * scale;
                    let py = (y as f32 + (sy as f32 + 0.5) / 3.0) * scale;
                    let sample = sample_at(px, py, bg, link, node, pulse);
                    for c in 0..4 {
                        acc[c] += sample[c];
                    }
                }
            }

            let idx = ((y * size + x) * 4) as usize;
            for c in 0..4 {
                pixels[idx + c] = (acc[c] / 9.0).round().clamp(0.0, 255.0) as u8;
            }
        }
    }

    Rgba {
        width: size,
        height: size,
        pixels,
    }
}

/// Цвет одного подпикселя: слои накладываются снизу вверх.
fn sample_at(
    x: f32,
    y: f32,
    bg: Option<[u8; 3]>,
    link: [u8; 3],
    node: [u8; 3],
    pulse: [u8; 3],
) -> [f32; 4] {
    let p = (x, y);
    let mut out = [0.0f32; 4];

    if let Some(bg) = bg {
        // Подложка со скруглением, поле по краю оставлено намеренно:
        // на панели задач иконка не должна упираться в соседей.
        if sd_round_box(p, (128.0, 128.0), (120.0, 120.0), 56.0) <= 0.0 {
            out = opaque(bg);
        }
    }

    for i in 0..NODES.len() {
        let a = NODES[i];
        let b = NODES[(i + 1) % NODES.len()];
        // Нижнее ребро треугольника совпало бы с линией пульса — пропускаем его.
        if i == 0 {
            continue;
        }
        if sd_segment(p, a, b) <= LINK_W / 2.0 {
            out = over(opaque(link), out);
        }
    }

    for w in PULSE_PATH.windows(2) {
        if sd_segment(p, w[0], w[1]) <= PULSE_W / 2.0 {
            out = over(opaque(pulse), out);
        }
    }

    for &c in &NODES {
        if dist(p, c) <= NODE_R {
            out = over(opaque(node), out);
        }
    }

    out
}

fn opaque(rgb: [u8; 3]) -> [f32; 4] {
    [rgb[0] as f32, rgb[1] as f32, rgb[2] as f32, 255.0]
}

/// Непрозрачное наложение: подпиксель либо занят цветом, либо нет,
/// полутона появляются уже при усреднении сетки 3×3.
fn over(top: [f32; 4], _bottom: [f32; 4]) -> [f32; 4] {
    top
}

fn dist(p: (f32, f32), c: (f32, f32)) -> f32 {
    ((p.0 - c.0).powi(2) + (p.1 - c.1).powi(2)).sqrt()
}

/// Знаковое расстояние до скруглённого прямоугольника.
fn sd_round_box(p: (f32, f32), center: (f32, f32), half: (f32, f32), r: f32) -> f32 {
    let qx = (p.0 - center.0).abs() - (half.0 - r);
    let qy = (p.1 - center.1).abs() - (half.1 - r);
    let ox = qx.max(0.0);
    let oy = qy.max(0.0);
    (ox * ox + oy * oy).sqrt() + qx.max(qy).min(0.0) - r
}

/// Расстояние от точки до отрезка.
fn sd_segment(p: (f32, f32), a: (f32, f32), b: (f32, f32)) -> f32 {
    let (pax, pay) = (p.0 - a.0, p.1 - a.1);
    let (bax, bay) = (b.0 - a.0, b.1 - a.1);
    let len2 = bax * bax + bay * bay;
    let t = if len2 == 0.0 {
        0.0
    } else {
        ((pax * bax + pay * bay) / len2).clamp(0.0, 1.0)
    };
    ((pax - bax * t).powi(2) + (pay - bay * t).powi(2)).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_has_expected_shape() {
        let img = render(32);
        assert_eq!(img.width, 32);
        assert_eq!(img.pixels.len(), 32 * 32 * 4);
    }

    #[test]
    fn background_fills_the_centre_and_leaves_corners_clear() {
        let img = render(64);
        let at = |x: u32, y: u32| img.pixels[((y * 64 + x) * 4 + 3) as usize];
        assert_eq!(at(32, 32), 255, "центр логотипа должен быть непрозрачным");
        assert_eq!(at(0, 0), 0, "угол за скруглением должен быть прозрачным");
    }

    #[test]
    fn tinted_variant_has_no_background() {
        let img = render_tinted(64, [255, 0, 0]);
        let alpha_at = |x: u32, y: u32| img.pixels[((y * 64 + x) * 4 + 3) as usize];
        // Точка внутри подложки, но вне линий и узлов.
        assert_eq!(alpha_at(12, 56), 0);
    }
}
