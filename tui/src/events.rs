use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::App;

pub fn handle_key(app: &mut App, key: KeyEvent) {
    // crossterm emits a Press and a Release (and sometimes Repeat) event for a
    // single physical keypress. Only act on Press, otherwise every character is
    // handled twice. Mirrors CodeWhale's `if key.kind != KeyEventKind::Press`.
    if key.kind != KeyEventKind::Press {
        return;
    }

    // A transient toast (e.g. "Copied …") lives until the next key press.
    app.toast.clear();

    if app.setup.is_some() {
        // Allow Ctrl+C to quit even from the setup wizard.
        if let (KeyCode::Char('c'), KeyModifiers::CONTROL) = (key.code, key.modifiers) {
            app.running = false;
            return;
        }
        app.setup_handle_key(key);
        return;
    }

    if app.pending_spear.is_some() {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => app.confirm_spear(),
            KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => app.dismiss_spear(),
            _ => {}
        }
        return;
    }

    match (key.code, key.modifiers) {
        (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
            if app.worker_active {
                app.stop_worker();
            } else {
                app.running = false;
            }
        }
        (KeyCode::Char('s'), KeyModifiers::CONTROL) => app.save_session(),
        (KeyCode::Char('r'), KeyModifiers::CONTROL) => app.restore_session(),
        (KeyCode::Char('t'), KeyModifiers::CONTROL) => app.show_reasoning = !app.show_reasoning,
        (KeyCode::Char('p'), KeyModifiers::CONTROL) => app.recall_history(true),
        (KeyCode::Char('n'), KeyModifiers::CONTROL) => app.recall_history(false),
        (KeyCode::Char('y'), KeyModifiers::CONTROL) => app.copy_active_pane(),
        (KeyCode::Left, modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            app.cycle_active_pane(true)
        }
        (KeyCode::Right, modifiers) if modifiers.contains(KeyModifiers::CONTROL) => {
            app.cycle_active_pane(false)
        }
        (KeyCode::F(5), _) => app.show_attack_chain = !app.show_attack_chain,
        (KeyCode::Tab, _) => app.cycle_mode(),
        (KeyCode::BackTab, _) => app.cycle_permission(),
        (KeyCode::Up, _) if app.palette_visible() => app.select_next_command(false),
        (KeyCode::Down, _) if app.palette_visible() => app.select_next_command(true),
        (KeyCode::Up, _) => app.scroll_active_pane(false),
        (KeyCode::Down, _) => app.scroll_active_pane(true),
        // Keyboard page scrolling — compensates for disabling mouse capture
        // (which we turned off so users can select/copy text from the terminal).
        (KeyCode::PageUp, _) => app.scroll_active_pane(false),
        (KeyCode::PageDown, _) => app.scroll_active_pane(true),
        (KeyCode::Esc, _) => app.clear_composer(),
        (KeyCode::Enter, _) if app.palette_visible() && app.should_complete_selected_command() => {
            app.accept_selected_command();
        }
        (KeyCode::Enter, _) => app.submit(),
        (KeyCode::Backspace, _) => app.delete_input(),
        (KeyCode::Delete, _) => app.delete_forward_input(),
        (KeyCode::Left, _) => app.move_input_cursor(false),
        (KeyCode::Right, _) => app.move_input_cursor(true),
        (KeyCode::Home, _) => app.move_input_cursor_to_edge(false),
        (KeyCode::End, _) => app.move_input_cursor_to_edge(true),
        (KeyCode::Char(character), modifiers) if !modifiers.contains(KeyModifiers::CONTROL) => {
            app.append_input(character)
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::handle_key;
    use crate::app::{ActivePane, App, ExecutionMode, PermissionMode};

    #[test]
    fn tab_cycles_execution_mode_and_shift_tab_cycles_permission() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);

        handle_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT),
        );

        assert_eq!(app.mode, ExecutionMode::Agent);
        assert_eq!(app.permission, PermissionMode::FullAccess);
    }

    #[test]
    fn arrows_scroll_the_selected_inspector() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.active_pane = ActivePane::Findings;

        handle_key(&mut app, KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));

        assert_eq!(app.findings_scroll, 1);
        assert_eq!(app.transcript_scroll, 0);
    }

    #[test]
    fn spear_confirmation_captures_shortcuts() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.pending_spear = Some(vec!["spear".into(), "run".into()]);

        handle_key(&mut app, KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));

        assert_eq!(app.mode, ExecutionMode::Plan);
        assert!(app.pending_spear.is_some());
    }

    #[test]
    fn enter_executes_an_exact_command_instead_of_refilling_it() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.input = "/plan".into();

        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(app.input.is_empty());
        assert!(app.transcript.iter().any(|item| item.text == "> /plan"));
    }

    #[test]
    fn cursor_and_history_shortcuts_edit_the_composer() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.input = "/helpx".into();
        app.input_cursor = app.input.len();

        handle_key(&mut app, KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        handle_key(&mut app, KeyEvent::new(KeyCode::Delete, KeyModifiers::NONE));
        handle_key(&mut app, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL),
        );

        assert_eq!(app.input, "/help");
    }

    #[test]
    fn ctrl_c_aborts_a_running_worker_instead_of_quitting() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.worker_active = true;

        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );

        assert!(!app.worker_active);
        assert!(app.running, "TUI should stay open after aborting a run");
    }

    #[test]
    fn ctrl_c_quits_when_no_worker_is_running() {
        let (sender, _) = mpsc::channel();
        let mut app = App::new(sender);
        app.worker_active = false;

        handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        );

        assert!(!app.running);
    }
}
