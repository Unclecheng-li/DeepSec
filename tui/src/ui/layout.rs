use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::app::{ActivePane, App, PROVIDERS};
use crate::theme;
use crate::views::skills_manager;

/// Full-screen first-run API configuration wizard.
pub fn render_setup(frame: &mut Frame, app: &App) {
    let setup = match &app.setup {
        Some(s) => s,
        None => return,
    };
    let area = frame.area();
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(theme::CORAL)
        .title(" DeepSec · API Setup ");
    let inner = outer.inner(area);
    frame.render_widget(outer, area);

    let steps = ["1.Provider", "2.API Key", "3.Base URL", "4.Model"];
    let step_label = steps.get(setup.step as usize).copied().unwrap_or("");

    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::from(Span::styled(
        "Configure your LLM provider to enable L3 semantic review and Agent modes.",
        Style::default().fg(theme::TEXT_HINT),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        format!("Step: {step_label}"),
        Style::default()
            .fg(theme::ACTION)
            .add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(""));

    if setup.step == 0 {
        for (i, p) in PROVIDERS.iter().enumerate() {
            let marker = if i == setup.provider_index { "▶ " } else { "  " };
            let style = if i == setup.provider_index {
                Style::default()
                    .fg(theme::ACTION)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::TEXT_BODY)
            };
            lines.push(Line::from(Span::styled(
                format!("{marker}{}  ({})", p.label, p.name),
                style,
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Up/Down select · Enter confirm",
            Style::default().fg(theme::TEXT_HINT),
        )));
    } else {
        let (prompt, prefix, field_val, mask) = match setup.step {
            1 => ("API Key", "API Key: ", setup.api_key.as_str(), true),
            2 => ("Base URL", "Base URL: ", setup.base_url.as_str(), false),
            3 => ("Model", "Model: ", setup.model.as_str(), false),
            _ => ("", "", "", false),
        };
        let display = if field_val.is_empty() {
            "<type here>".to_string()
        } else if mask {
            "*".repeat(field_val.chars().count())
        } else {
            field_val.to_string()
        };
        lines.push(Line::from(Span::styled(
            format!("{prompt}: {display}"),
            Style::default().fg(theme::TEXT_BODY),
        )));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "Type to edit · Enter next · Esc skip",
            Style::default().fg(theme::TEXT_HINT),
        )));
        let _ = prefix;
    }

    if !setup.message.is_empty() {
        lines.push(Line::from(""));
        let msg_style = if setup.error {
            Style::default().fg(theme::CORAL)
        } else {
            Style::default().fg(theme::TEXT_HINT)
        };
        lines.push(Line::from(Span::styled(setup.message.clone(), msg_style)));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);

    // Place the terminal cursor on the editable line for text steps.
    if setup.step != 0 {
        let prefix = match setup.step {
            1 => "API Key: ",
            2 => "Base URL: ",
            3 => "Model: ",
            _ => "",
        };
        let input_line_y = inner.y + 4;
        let cursor_x = inner
            .x
            .saturating_add(prefix.chars().count() as u16)
            .saturating_add(setup.cursor as u16)
            .min(inner.right().saturating_sub(1));
        frame.set_cursor_position((cursor_x, input_line_y));
    }
}

pub fn render(frame: &mut Frame, app: &App) {
    if app.setup.is_some() {
        render_setup(frame, app);
        return;
    }
    frame.render_widget(
        Block::default().style(Style::default().bg(theme::BG)),
        frame.area(),
    );
    // Compact single-line composer (CodeWhale Compact density): one input row,
    // no bordered title box that reads as a second line. The command palette and
    // the spear-confirmation prompt get their own taller regions when active.
    let composer_height = if app.pending_spear.is_some() {
        3
    } else if app.palette_visible() {
        7
    } else {
        1
    };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(composer_height),
            Constraint::Length(1),
        ])
        .split(frame.area());
    render_header(frame, app, rows[0]);
    render_phase_strip(frame, app, rows[1]);
    render_workbench(frame, app, rows[2]);
    render_composer(frame, app, rows[3]);
    render_hotbar(frame, app, rows[4]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(
            " DeepSec ",
            Style::default().fg(theme::ACTION).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", app.mode.label()),
            Style::default()
                .fg(theme::mode_color(app.mode.label()))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("| {} ", app.permission.label()),
            Style::default().fg(theme::permission_color(app.permission.label())),
        ),
        Span::raw("| "),
    ];
    if app.worker_active {
        // Live "working" cluster: spinning glyph, bouncing equalizer, and a
        // running elapsed-time readout — all animate off the wall clock so the
        // surface feels alive without any extra state.
        spans.push(Span::styled(
            format!("{} running", theme::spinner_frame(true)),
            Style::default().fg(theme::GOLD),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            theme::equalizer_frame(),
            Style::default().fg(theme::SEAFOAM),
        ));
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            theme::elapsed_label(app.worker_started_at),
            Style::default().fg(theme::TEXT_SOFT),
        ));
    } else {
        spans.push(Span::styled("idle", Style::default().fg(theme::TEXT_HINT)));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(theme::CHROME)),
        area,
    );
}

/// Live progress bar — mirrors CodeWhale's phase strip so a running scan shows
/// its current phase and finding count instead of a frozen transcript.
fn render_phase_strip(frame: &mut Frame, app: &App, area: Rect) {
    let line = if app.worker_active {
        if let Some(receipt) = app.active_receipt.as_ref() {
            let mut spans = vec![Span::styled(
                format!(" {} {}  ·  ", theme::spinner_frame(true), receipt.phase),
                Style::default().fg(theme::SEAFOAM),
            )];
            // The finding count pulses gold while a run is live and has already
            // surfaced something, so a fresh hit reads as a heartbeat.
            let fc_style = if receipt.findings > 0 && theme::blink_on() {
                Style::default()
                    .fg(theme::GOLD)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme::SEAFOAM)
            };
            spans.push(Span::styled(
                format!("{} finding(s)", receipt.findings),
                fc_style,
            ));
            spans.push(Span::styled(
                format!("  ·  {}", receipt.command),
                Style::default().fg(theme::SEAFOAM),
            ));
            Line::from(spans)
        } else {
            Line::from(Span::styled(
                format!(" {} working", theme::spinner_frame(true)),
                Style::default().fg(theme::SEAFOAM),
            ))
        }
    } else if let Some(receipt) = app.last_receipt.as_ref() {
        Line::from(Span::styled(
            format!(
                " {}  ·  {} finding(s)  ·  {}",
                receipt.phase, receipt.findings, receipt.command
            ),
            Style::default().fg(theme::TEXT_HINT),
        ))
    } else {
        Line::from(Span::styled(" ready", Style::default().fg(theme::TEXT_HINT)))
    };
    frame.render_widget(
        Paragraph::new(line).style(Style::default().bg(theme::CHROME)),
        area,
    );
}

fn render_workbench(frame: &mut Frame, app: &App, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(28),
            Constraint::Min(36),
            Constraint::Length(40),
        ])
        .split(area);
    let sidebar = skills_manager::render(app).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(theme::BORDER)
            .style(Style::default().bg(theme::PANEL))
            .title(if app.active_pane == ActivePane::Workspace {
                "Workspace *"
            } else {
                "Workspace"
            }),
    );
    frame.render_widget(sidebar, panels[0]);
    crate::ui::transcript::render(frame, app, panels[1]);
    crate::ui::findings::render(frame, app, panels[2]);
}

fn render_composer(frame: &mut Frame, app: &App, area: Rect) {
    if app.pending_spear.is_some() {
        frame.render_widget(
            Paragraph::new("TUI confirmation is required. Press Y to ask DeepSec to verify the signed scope and start, or Esc to cancel.")
                .wrap(Wrap { trim: true })
                .block(Block::default().borders(Borders::ALL).border_style(theme::CORAL).title("Spear confirmation required")),
            area,
        );
        return;
    }

    if app.palette_visible() {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(6), Constraint::Length(1)])
            .split(area);
        render_command_palette(frame, app, rows[0]);
        render_composer_input(frame, app, rows[1]);
    } else {
        render_composer_input(frame, app, area);
    }
}

fn render_composer_input(frame: &mut Frame, app: &App, composer_area: Rect) {
    let content = if app.input.is_empty() {
        "Type / for commands"
    } else {
        app.input.as_str()
    };
    let style = if app.input.is_empty() {
        Style::default().fg(theme::TEXT_HINT)
    } else {
        Style::default().fg(theme::TEXT_BODY)
    };
    // Single-line prompt — no bordered title box (which read as a second line).
    // The leading marker + text + cursor all live on this one row.
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " > ",
                Style::default()
                    .fg(theme::ACTION)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(content, style),
        ]))
        .style(Style::default().bg(theme::PLATE)),
        composer_area,
    );
    if !app.input.is_empty() {
        let cursor_x = composer_area
            .x
            .saturating_add(3)
            .saturating_add(app.input[..app.input_cursor].chars().count() as u16)
            .min(composer_area.right().saturating_sub(1));
        frame.set_cursor_position((cursor_x, composer_area.y));
    }
}

fn render_command_palette(frame: &mut Frame, app: &App, area: Rect) {
    let commands = app.suggested_commands();
    let items = commands
        .iter()
        .map(|item| {
            ListItem::new(Line::from(vec![
                Span::styled(item.command, Style::default().fg(theme::ACTION)),
                Span::raw("  "),
                Span::styled(item.description, Style::default().fg(theme::TEXT_MUTED)),
            ]))
        })
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.palette_selection));
    frame.render_stateful_widget(
        List::new(items)
            .highlight_style(
                Style::default()
                    .fg(theme::TEXT_BODY)
                    .bg(theme::PLATE)
                    .add_modifier(Modifier::BOLD),
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(theme::BORDER)
                    .title("Commands"),
            ),
        area,
        &mut state,
    );
}

fn render_hotbar(frame: &mut Frame, app: &App, area: Rect) {
    let (text, style) = if !app.toast.is_empty() {
        (
            app.toast.as_str(),
            Style::default()
                .fg(theme::SEAFOAM)
                .add_modifier(Modifier::BOLD),
        )
    } else if app.pending_spear.is_some() {
        (
            " Y request scope verification | Esc cancel",
            Style::default().fg(theme::TEXT_HINT),
        )
    } else if app.worker_active {
        (
            " Running — Ctrl+C abort | Tab mode | ↑/↓ scroll | Ctrl+Y copy pane",
            Style::default().fg(theme::TEXT_HINT),
        )
    } else {
        (
            " Tab mode | Shift+Tab safeguard | Ctrl+P/N history | Ctrl+←/→ panel | ↑/↓ scroll | Ctrl+T thinking | F5 chain | Ctrl+S save | Ctrl+R restore | Ctrl+Y copy pane | Ctrl+C exit",
            Style::default().fg(theme::TEXT_HINT),
        )
    };
    frame.render_widget(
        Paragraph::new(Span::styled(text, style)).style(Style::default().bg(theme::CHROME)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Instant;

    use ratatui::{backend::TestBackend, Terminal};

    use super::render;
    use crate::app::{App, OperationReceipt};

    #[test]
    fn renders_a_composer_centered_security_workbench() {
        let (sender, _) = mpsc::channel();
        let app = App::new(sender);
        let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

        terminal.draw(|frame| render(frame, &app)).unwrap();

        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Session transcript"));
        assert!(rendered.contains("Findings inspector (0)"));
        assert!(rendered.contains("Type / for commands"));
        assert!(rendered.contains("Tab mode"));
        assert!(rendered.contains("ready"));
        assert!(!rendered.contains("[Skills] [Findings] [Output]"));
    }

    #[test]
    fn header_shows_live_timer_and_running_state_while_a_worker_is_active() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.worker_active = true;
        app.worker_started_at = Some(Instant::now());
        app.active_receipt = Some(OperationReceipt {
            command: "spear run https://example.com".into(),
            phase: "Running".into(),
            findings: 0,
        });
        let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

        terminal.draw(|frame| render(frame, &app)).unwrap();

        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("running"), "header must read 'running'");
        assert!(rendered.contains("⏱"), "header must show the live elapsed timer");
    }

    #[test]
    fn slash_input_renders_the_command_palette() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.insert_text("/");
        let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

        terminal.draw(|frame| render(frame, &app)).unwrap();

        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Commands"));
        assert!(rendered.contains("/shield scan"));
    }

    #[test]
    fn composer_placeholder_renders_on_a_single_row() {
        let (sender, _) = mpsc::channel();
        let app = App::new(sender); // empty input -> placeholder path
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| render(frame, &app)).unwrap();
        let buf = terminal.backend().buffer();
        let mut rows_with_placeholder = 0;
        for y in 0..24u16 {
            let line: String = (0..80u16)
                .map(|x| buf.cell((x, y)).map(|c| c.symbol().to_string()).unwrap_or_default())
                .collect();
            if line.contains("Type / for commands") {
                rows_with_placeholder += 1;
            }
        }
        assert_eq!(
            rows_with_placeholder, 1,
            "the composer placeholder must render on exactly one row"
        );
    }

    #[test]
    fn spear_confirmation_replaces_the_composer() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.pending_spear = Some(vec!["spear".into(), "run".into()]);
        let mut terminal = Terminal::new(TestBackend::new(120, 28)).unwrap();

        terminal.draw(|frame| render(frame, &app)).unwrap();

        let rendered = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("Spear confirmation required"));
        assert!(rendered.contains("Y request scope verification"));
    }
}
