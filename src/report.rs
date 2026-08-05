//! Текстовый отчёт: то же, что показано в окне, но в виде, который можно
//! скопировать и отправить в поддержку провайдера.
//!
//! Отчёт всегда полный — и простое объяснение, и техническое, и сырые данные.
//! Получатель заранее неизвестен: письмо может читать и оператор колл-центра,
//! и инженер.

use std::fmt::Write as _;

use crate::model::{Layer, Report, Status};
use crate::privileged::Capabilities;

/// Собирает отчёт целиком.
pub fn render(report: &Report, caps: Capabilities) -> String {
    let mut out = String::new();

    let _ = writeln!(out, "NETCHECKER — отчёт о состоянии подключения");
    let _ = writeln!(out, "Режим замеров: {}", caps.icmp.title());
    let _ = writeln!(
        out,
        "Права администратора: {}",
        if caps.elevated { "есть" } else { "нет" }
    );
    let _ = writeln!(out);

    let d = &report.diagnosis;
    let _ = writeln!(out, "ВЫВОД: {}", d.headline);
    let _ = writeln!(out, "{}", d.simple);
    if !d.expert.is_empty() {
        let _ = writeln!(out, "Технически: {}", d.expert);
    }
    if !d.actions.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "Что можно сделать:");
        for action in &d.actions {
            let _ = writeln!(out, "  - {action}");
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "СХЕМА СЕТИ");
    for node in &report.nodes {
        let address = node.address.clone().unwrap_or_else(|| "—".into());
        let _ = writeln!(
            out,
            "  [{:>2}] {:<16} {:<18} {}",
            node.status.glyph(),
            node.id.title(),
            address,
            node.subtitle
        );
    }
    if let Some((from, to)) = d.break_edge {
        let _ = writeln!(out, "  Обрыв на участке: {} -> {}", from.title(), to.title());
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "ПРОВЕРКИ ПО УРОВНЯМ");
    for layer in Layer::ALL {
        let checks: Vec<_> = report.checks_of(layer).collect();
        if checks.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n{} · {} — {}", layer.code(), layer.title(), layer.plain());
        for check in checks {
            let _ = writeln!(out, "  [{:>2}] {}", check.status.glyph(), check.title);
            if !check.simple.is_empty() {
                let _ = writeln!(out, "       {}", check.simple);
            }
            if !check.expert.is_empty() {
                let _ = writeln!(out, "       технически: {}", check.expert);
            }
            for line in &check.evidence {
                for sub in line.lines() {
                    let _ = writeln!(out, "         {sub}");
                }
            }
        }
    }

    let failures = report
        .checks
        .iter()
        .filter(|c| c.status == Status::Fail)
        .count();
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "Итого проверок: {}, из них не прошло: {failures}.",
        report.checks.len()
    );

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CheckResult, NodeId};
    use crate::privileged::IcmpBackend;

    fn caps() -> Capabilities {
        Capabilities {
            icmp: IcmpBackend::WindowsIcmpApi,
            elevated: false,
        }
    }

    #[test]
    fn empty_report_still_renders() {
        let text = render(&Report::new(), caps());
        assert!(text.contains("СХЕМА СЕТИ"));
        assert!(text.contains("Итого проверок: 0"));
    }

    /// Отчёт уходит человеку, который нас не видит, поэтому в нём должны быть
    /// оба объяснения и сырые данные — иначе он бесполезен как для оператора,
    /// так и для инженера.
    #[test]
    fn check_appears_with_both_explanations_and_evidence() {
        let mut report = Report::new();
        report.apply(
            CheckResult::new("t", Layer::L3Network, NodeId::Router, "Отклик роутера")
                .finish(Status::Fail, "Роутер не отвечает.", "ICMP: 4/4 без ответа.")
                .with_evidence("192.168.1.1: тайм-аут"),
        );

        let text = render(&report, caps());
        assert!(text.contains("Роутер не отвечает."));
        assert!(text.contains("ICMP: 4/4 без ответа."));
        assert!(text.contains("192.168.1.1: тайм-аут"));
        assert!(text.contains("не прошло: 1"));
    }
}
