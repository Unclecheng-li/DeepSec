use std::fs;
use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::app::{App, ExecutionMode, PermissionMode, TranscriptItem, TranscriptKind};
use crate::protocol::Finding;

#[derive(Deserialize, Serialize)]
pub struct SessionState {
    mode: String,
    #[serde(default)]
    permission: String,
    #[serde(default)]
    transcript: Vec<TranscriptItem>,
    #[serde(default)]
    history: Vec<String>,
    // Retained to open sessions written by the first DeepSec TUI release.
    #[serde(default)]
    messages: Vec<String>,
    #[serde(default)]
    findings: Vec<Finding>,
}

impl SessionState {
    pub fn from_app(app: &App) -> Self {
        Self {
            mode: app.mode.label().to_owned(),
            permission: app.permission.label().to_owned(),
            transcript: app.transcript.clone(),
            history: app.command_history.clone(),
            messages: Vec::new(),
            findings: app.findings.clone(),
        }
    }

    pub fn apply(self, app: &mut App) {
        app.mode = match self.mode.as_str() {
            "Agent" => ExecutionMode::Agent,
            "YOLO" => ExecutionMode::Yolo,
            _ => ExecutionMode::Plan,
        };
        app.permission = match self.permission.as_str() {
            "Ask" => PermissionMode::Ask,
            "Full access" => PermissionMode::FullAccess,
            _ => PermissionMode::AutoReview,
        };
        app.transcript = if self.transcript.is_empty() {
            self.messages
                .into_iter()
                .map(|text| TranscriptItem {
                    kind: TranscriptKind::System,
                    text,
                })
                .collect()
        } else {
            self.transcript
        };
        app.findings = self.findings;
        app.command_history = self.history;
        app.clear_composer();
        app.findings_scroll = 0;
        app.transcript_scroll = 0;
    }
}

pub fn session_path() -> PathBuf {
    std::env::var_os("DEEPSEC_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~").join(".deepsec"))
        .join("tui")
        .join("session.json")
}

pub fn save(state: &SessionState) -> io::Result<PathBuf> {
    let path = expand_home(session_path());
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &path,
        serde_json::to_vec_pretty(state).map_err(io::Error::other)?,
    )?;
    Ok(path)
}

pub fn load() -> io::Result<SessionState> {
    let path = expand_home(session_path());
    serde_json::from_slice(&fs::read(path)?).map_err(io::Error::other)
}

fn expand_home(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix("~\\").or_else(|| text.strip_prefix("~/")) {
        return std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(rest);
    }
    path
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::SessionState;
    use crate::app::{App, ExecutionMode, PermissionMode};

    #[test]
    fn session_round_trip_preserves_composer_history_and_posture() {
        let (sender, _) = mpsc::channel();
        let mut source = App::new(sender);
        source.insert_text("/help");
        source.submit();
        source.cycle_mode();
        source.cycle_permission();
        let state = SessionState::from_app(&source);

        let (target_sender, _) = mpsc::channel();
        let mut target = App::new(target_sender);
        state.apply(&mut target);

        assert_eq!(target.command_history, vec!["/help"]);
        assert_eq!(target.mode, ExecutionMode::Agent);
        assert_eq!(target.permission, PermissionMode::FullAccess);
        assert!(target.input.is_empty());
        assert!(target.transcript.iter().any(|item| item.text == "> /help"));
    }
}
