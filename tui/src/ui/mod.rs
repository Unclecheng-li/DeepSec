pub mod attack_chain;
pub mod findings;
pub mod layout;
pub mod transcript;

use ratatui::Frame;

use crate::app::App;

pub fn draw(frame: &mut Frame, app: &App) {
    if app.show_attack_chain {
        attack_chain::render(frame, app);
    } else {
        layout::render(frame, app);
    }
}
