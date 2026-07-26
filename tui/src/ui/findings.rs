use ratatui::{
    layout::Rect,
    style::Style,
    text::Span,
    widgets::{Block, Borders, List, ListItem, ListState},
    Frame,
};

use crate::app::{ActivePane, App};
use crate::theme;

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let items = app
        .findings
        .iter()
        .map(|finding| {
            let location = finding
                .line
                .map(|line| format!("{}:{line}", finding.target))
                .unwrap_or_else(|| finding.target.clone());
            let label = format!(
                "[{}] {} - {}",
                finding.severity.to_uppercase(),
                finding.title,
                location
            );
            ListItem::new(label).style(theme::severity_style(&finding.severity))
        })
        .collect::<Vec<_>>();
    let title = if app.active_pane == ActivePane::Findings {
        format!("Findings inspector ({}) *", app.findings.len())
    } else {
        format!("Findings inspector ({})", app.findings.len())
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::BORDER)
            .style(Style::default().bg(theme::PANEL))
            .title(Span::styled(title, Style::default().fg(theme::TEXT_SOFT))),
    );
    let mut state = ListState::default().with_offset(app.findings_scroll as usize);
    frame.render_stateful_widget(list, area, &mut state);
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use ratatui::{backend::TestBackend, Terminal};

    use super::render;
    use crate::{app::App, protocol::Finding, theme};

    #[test]
    fn renders_findings_with_their_severity_color() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.findings.push(Finding {
            id: "critical-1".into(),
            severity: "critical".into(),
            title: "Hardcoded credential".into(),
            target: "src/app.py".into(),
            line: Some(12),
            chain_depends_on: Vec::new(),
        });
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();

        terminal
            .draw(|frame| render(frame, &app, frame.area()))
            .unwrap();

        let buffer = terminal.backend().buffer();
        let rendered = buffer
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Findings inspector (1)"));
        assert!(buffer.content.iter().any(|cell| cell.fg == theme::ROSE));
    }
}
