use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
    Frame,
};

use crate::app::{ActivePane, App, TranscriptKind};
use crate::theme;

/// Build the rendered transcript lines, honouring the `show_reasoning` filter.
/// Shared by [`render`] and the auto-follow scroll logic in `app.rs` so both
/// compute the exact same wrapped line count.
pub fn build_lines(app: &App) -> Vec<Line<'static>> {
    app.transcript
        .iter()
        .filter(|item| app.show_reasoning || !matches!(item.kind, TranscriptKind::Reasoning))
        .map(|item| {
            let (prefix, style) = match item.kind {
                TranscriptKind::User => ("You  ", Style::default().add_modifier(Modifier::BOLD)),
                TranscriptKind::System => ("DeepSec  ", theme::transcript_style(&item.kind)),
                TranscriptKind::Status => ("Status  ", theme::transcript_style(&item.kind)),
                TranscriptKind::Log => ("Log  ", theme::transcript_style(&item.kind)),
                TranscriptKind::Reasoning => ("Thinking  ", theme::transcript_style(&item.kind)),
                TranscriptKind::Error => ("Error  ", theme::transcript_style(&item.kind)),
                TranscriptKind::Finding => ("Finding  ", theme::transcript_style(&item.kind)),
            };
            Line::from(vec![
                Span::styled(prefix, style.add_modifier(Modifier::BOLD)),
                Span::styled(item.text.clone(), style),
            ])
        })
        .collect::<Vec<_>>()
}

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let lines = build_lines(app);
    let title = if app.active_pane == ActivePane::Transcript {
        "Session transcript *"
    } else {
        "Session transcript"
    };
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.transcript_scroll, 0))
            .wrap(Wrap { trim: false })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::BORDER)
                    .style(Style::default().bg(theme::PANEL))
                    .title(Span::styled(title, Style::default().fg(theme::TEXT_SOFT))),
            ),
        area,
    );
}
