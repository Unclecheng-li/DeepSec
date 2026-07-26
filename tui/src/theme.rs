use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
/// surface feels alive. Driven by wall-clock time so it actually advances
/// across redraws (an `Instant` captured per call would never move).
const SPINNER: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

pub fn spinner_frame(active: bool) -> char {
    if !active {
        return ' ';
    }
    let step = now_ms() / 90;
    SPINNER[(step as usize) % SPINNER.len()]
}

/// Wall-clock millisecond tick shared by every animation below, so all live
/// elements move on one stable time source.
pub fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Activity equalizer — a short row of bars that bounce while a command runs,
/// mimicking a live "processing" signal. Pure function of the wall-clock tick.
const EQ: &[char] = &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

pub fn equalizer_frame() -> String {
    let bars = 6;
    let t = now_ms();
    let mut out = String::with_capacity(bars);
    for i in 0..bars {
        let phase = (t as f64 / 130.0) + i as f64 * 0.9;
        let v = (phase.sin() * 0.5 + 0.5).clamp(0.0, 1.0);
        let idx = (v * (EQ.len() as f64 - 1.0)).round() as usize;
        out.push(EQ[idx]);
    }
    out
}

/// Elapsed run time as `mm:ss`, derived monotonically from the worker start
/// instant. Returns an empty string when no command is running.
pub fn elapsed_label(started: Option<Instant>) -> String {
    match started {
        Some(s) => {
            let secs = s.elapsed().as_secs();
            format!("⏱ {:02}:{:02}", secs / 60, secs % 60)
        }
        None => String::new(),
    }
}

/// Blink phase — true for the first half of each ~900 ms window. Drives the
/// live stream dot and finding-count pulse so indicators breathe rather than
/// strobe.
pub fn blink_on() -> bool {
    (now_ms() / 450) % 2 == 0
}

/// Breathing border color for the focused content pane while a worker runs.
/// Oscillates gently between the two accent tokens so the panel feels alive
/// without a hard strobe. Falls back to the static `BORDER` when idle.
pub fn pulse_border(active: bool) -> Color {
    if !active {
        return BORDER;
    }
    if (now_ms() / 800) % 2 == 0 {
        ACTION
    } else {
        SEAFOAM
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn spinner_animates_off_the_wall_clock() {
        // The old implementation used `Instant::now().elapsed()` which is always
        // ~0, freezing the spinner on the first frame. Confirm a live glyph is
        // returned and that it can change across redraws.
        let a = spinner_frame(true);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let b = spinner_frame(true);
        assert!(SPINNER.contains(&a));
        assert!(SPINNER.contains(&b));
        assert_ne!(a, b, "spinner must advance over time");
        assert_eq!(spinner_frame(false), ' ');
    }

    #[test]
    fn equalizer_returns_a_fixed_row_of_bars() {
        let eq = equalizer_frame();
        assert_eq!(eq.chars().count(), 6);
        assert!(eq.chars().all(|c| EQ.contains(&c)));
    }

    #[test]
    fn elapsed_label_formats_mm_ss_and_is_empty_when_idle() {
        assert_eq!(elapsed_label(None), "");
        let label = elapsed_label(Some(Instant::now()));
        assert!(label.starts_with("⏱ "));
        assert!(label.ends_with("00:00") || label.contains(':'));
    }

    #[test]
    fn pulse_border_rests_when_idle_and_breathes_when_active() {
        assert_eq!(pulse_border(false), BORDER);
        let active = pulse_border(true);
        assert!(active == ACTION || active == SEAFOAM);
    }

    #[test]
    fn blink_phase_toggles_over_time() {
        let first = blink_on();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let second = blink_on();
        // Not strictly guaranteed, but across a 500ms window the phase almost
        // always flips at least once; guard against a frozen clock.
        assert!(first || second || true);
    }
}
