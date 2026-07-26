use ratatui::style::{Color, Style};

use crate::app::TranscriptKind;

/// CodeWhale "whale deep" dark palette — copied verbatim from
/// `crates/tui/src/palette/tokens.rs` so the DeepSec TUI shares the same
/// visual grammar. No custom red/orange scheme: the accent that owns
/// interaction on dark is `ACTION` (blue), just like CodeWhale.
pub const BG: Color = Color::Rgb(3, 7, 13); // #03070D deep field
pub const CHROME: Color = Color::Rgb(8, 17, 28); // #08111C ink / chrome
pub const PANEL: Color = Color::Rgb(14, 23, 41); // #0E1729 panel surface
pub const PLATE: Color = Color::Rgb(22, 34, 56); // #162238 composer plate
pub const BORDER: Color = Color::Rgb(38, 62, 92); // #263E5C blue @ 25%

pub const TEXT_BODY: Color = Color::Rgb(246, 242, 232); // #F6F2E8 whale ivory
pub const TEXT_SOFT: Color = Color::Rgb(182, 192, 212); // #B6C0D4
pub const TEXT_MUTED: Color = Color::Rgb(147, 160, 184); // #93A0B8
pub const TEXT_HINT: Color = Color::Rgb(132, 145, 170); // #8491AA

pub const ACTION: Color = Color::Rgb(106, 174, 242); // #6AAEF2 blue — owns interaction
pub const SEAFOAM: Color = Color::Rgb(79, 209, 197); // #4FD1C5 accent secondary
pub const GOLD: Color = Color::Rgb(246, 196, 83); // #F6C453 signal gold
pub const ROSE: Color = Color::Rgb(255, 134, 178); // #FF86B2 danger
pub const CORAL: Color = Color::Rgb(255, 122, 89); // #FF7A59 warning
pub const SUCCESS: Color = Color::Rgb(87, 199, 133); // #57C785 diff added / success
pub const MODE_AGENT: Color = Color::Rgb(118, 181, 245); // #76B5F5
pub const REASONING: Color = Color::Rgb(224, 153, 72); // #E09948 thinking

/// Transcript line styling, aligned with CodeWhale's semantic colors.
pub fn transcript_style(kind: &TranscriptKind) -> Style {
    match kind {
        TranscriptKind::User => Style::default().fg(TEXT_BODY),
        TranscriptKind::System => Style::default().fg(ACTION),
        TranscriptKind::Status => Style::default().fg(SEAFOAM),
        TranscriptKind::Log => Style::default().fg(TEXT_MUTED),
        TranscriptKind::Reasoning => Style::default().fg(REASONING),
        TranscriptKind::Error => Style::default().fg(ROSE).add_modifier(ratatui::style::Modifier::BOLD),
        TranscriptKind::Finding => Style::default().fg(GOLD),
    }
}

/// Severity colors reuse CodeWhale's danger/warning/gold/seafoam grammar.
pub fn severity_style(severity: &str) -> Style {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => Style::default().fg(ROSE).add_modifier(ratatui::style::Modifier::BOLD),
        "high" => Style::default().fg(CORAL),
        "medium" => Style::default().fg(GOLD),
        "low" => Style::default().fg(SEAFOAM),
        _ => Style::default().fg(TEXT_HINT),
    }
}

/// Mode badge color — mirrors CodeWhale's mode-specific accent tokens.
pub fn mode_color(label: &str) -> Color {
    match label {
        "Agent" => MODE_AGENT,
        "YOLO" => ROSE,
        _ => TEXT_HINT,
    }
}

/// Permission posture color.
pub fn permission_color(label: &str) -> Color {
    match label {
        "Ask" => CORAL,
        "Auto-review" => ACTION,
        "Full access" => SEAFOAM,
        _ => TEXT_HINT,
    }
}

/// Live spinner — CodeWhale keeps a rotating glyph while a worker runs so the
/// surface feels alive. Index derives from wall-clock time, no app state.
const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub fn spinner_frame(active: bool) -> char {
    if !active {
        return ' ';
    }
    let step = std::time::Instant::now().elapsed().as_millis() / 100;
    SPINNER[(step as usize) % SPINNER.len()]
}
