use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug)]
pub enum AppEvent {
    Stream(StreamEvent),
    Error(String),
    Finished(bool),
}

#[derive(Clone, Debug)]
pub enum StreamEvent {
    Status(String),
    Finding(Finding),
    Reasoning(String),
    Log(String),
    Complete(String),
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Finding {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub line: Option<u64>,
    #[serde(default)]
    pub chain_depends_on: Vec<String>,
}

impl Finding {
    pub fn summary(&self) -> String {
        let location = self
            .line
            .map(|line| format!("{}:{line}", self.target))
            .unwrap_or_else(|| self.target.clone());
        format!(
            "[{}] {} ({})",
            self.severity.to_uppercase(),
            self.title,
            location
        )
    }
}

pub fn parse_stream_line(line: &str) -> Option<StreamEvent> {
    let value: Value = serde_json::from_str(line).ok()?;
    let kind = value.get("type")?.as_str()?;
    match kind {
        "status" => Some(StreamEvent::Status(
            value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("running")
                .to_owned(),
        )),
        "finding" => serde_json::from_value(value.get("finding")?.clone())
            .ok()
            .map(StreamEvent::Finding),
        "reasoning" | "thinking" => Some(StreamEvent::Reasoning(
            value
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )),
        "log" => Some(StreamEvent::Log(
            value
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )),
        "complete" => {
            let findings = value
                .get("result")
                .and_then(|result| result.get("findings"))
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            Some(StreamEvent::Complete(format!(
                "Scan completed: {findings} finding(s)."
            )))
        }
        _ => None,
    }
}
