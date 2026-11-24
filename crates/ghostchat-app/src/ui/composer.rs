//! Composer behavior: where a typed line goes, the slash-command suggestion
//! list (Tab completes, Up/Down pick), and the custom focus operation that the
//! iced 0.13 text editor lacks.

use super::files::SlashKey;
use super::{composer_container_id, slash, App, Message};
use crate::inbox::Conversation;
use crate::mesh_worker::{self, Command};
use iced::advanced::widget::{self, operation, Id, Operation};
use iced::widget::text_editor;
use iced::{keyboard, Rectangle, Task};

impl App {
    pub(super) fn command_for(&self, line: &str) -> Option<Command> {
        // Commands are single-token lines; trim for matching, but send plain
        // messages with their leading indentation intact so pasted code keeps
        // its shape.
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }
        if trimmed.starts_with('/') {
            return mesh_worker::parse_command_line(trimmed);
        }
        let line = line.trim_end();
        match &self.selected {
            Conversation::Mesh => Some(Command::Public(line.into())),
            Conversation::Dm(id) => Some(Command::Private { to: id.clone(), content: line.into() }),
            Conversation::Geo(cell) => {
                Some(Command::Geo { cell: cell.clone(), text: line.into(), teleported: self.is_teleported(cell) })
            }
            Conversation::GeoDm { cell, pubkey } => {
                Some(Command::GeoDm { cell: cell.clone(), pubkey: pubkey.clone(), text: line.into() })
            }
            Conversation::Group(_) => Some(Command::GroupSend(line.into())),
        }
    }

    pub(super) fn slash_suggestions(&self) -> Vec<&'static slash::SlashCommand> {
        slash::suggestions(&self.draft, &self.selected)
    }

    /// Put suggestion `index` in the draft. Returns true when it takes arguments.
    pub(super) fn accept_suggestion(&mut self, index: usize) -> bool {
        let Some(command) = self.slash_suggestions().get(index).copied() else {
            return false;
        };
        self.draft = slash::complete(command);
        self.slash_pick = 0;
        self.replace_composer();
        !command.args.is_empty()
    }

    pub(super) fn on_slash_key(&mut self, key: SlashKey) -> Task<Message> {
        let count = self.slash_suggestions().len();
        if count == 0 {
            return Task::none();
        }
        match key {
            SlashKey::Up => self.slash_pick = (self.slash_pick + count - 1) % count,
            SlashKey::Down => self.slash_pick = (self.slash_pick + 1) % count,
            SlashKey::Complete => {
                self.accept_suggestion(self.slash_pick);
                return focus_composer();
            }
        }
        Task::none()
    }
}

/// Enter sends, Shift+Enter breaks the line, and Tab/Up/Down only steer the
/// suggestion list while it is showing. Everything else is the stock editor.
pub(super) fn editor_key_binding(
    suggestions: bool,
) -> impl Fn(text_editor::KeyPress) -> Option<text_editor::Binding<Message>> {
    move |press| {
        if press.status == text_editor::Status::Focused {
            use keyboard::key::Named;
            match press.key.as_ref() {
                keyboard::Key::Named(Named::Enter) if press.modifiers.shift() => {
                    return Some(text_editor::Binding::Enter);
                }
                keyboard::Key::Named(Named::Enter) => {
                    return Some(text_editor::Binding::Custom(Message::Submit));
                }
                keyboard::Key::Named(Named::Tab) if suggestions => {
                    return Some(text_editor::Binding::Custom(Message::SlashKey(SlashKey::Complete)));
                }
                keyboard::Key::Named(Named::ArrowUp) if suggestions => {
                    return Some(text_editor::Binding::Custom(Message::SlashKey(SlashKey::Up)));
                }
                keyboard::Key::Named(Named::ArrowDown) if suggestions => {
                    return Some(text_editor::Binding::Custom(Message::SlashKey(SlashKey::Down)));
                }
                _ => {}
            }
        }
        text_editor::Binding::from_key_press(press)
    }
}

/// Keep typing after a completion: focus the editor.
pub(super) fn focus_composer() -> Task<Message> {
    widget::operate(FocusEditor { target: composer_container_id().into(), entered: false, done: false })
}

/// iced 0.13's `text_editor` does not expose an `Id`, so `focusable::focus`
/// cannot reach it. Descend the tree until the composer's wrapper container is
/// entered, then focus its first (only) focusable child.
struct FocusEditor {
    target: Id,
    entered: bool,
    done: bool,
}

impl<T> Operation<T> for FocusEditor {
    fn container(
        &mut self,
        id: Option<&Id>,
        _bounds: Rectangle,
        operate_on_children: &mut dyn FnMut(&mut dyn Operation<T>),
    ) {
        if self.done {
            return;
        }
        if id == Some(&self.target) {
            self.entered = true;
        }
        operate_on_children(self);
    }

    fn focusable(&mut self, state: &mut dyn operation::Focusable, _id: Option<&Id>) {
        if self.entered && !self.done {
            state.focus();
            self.done = true;
        }
    }
}
