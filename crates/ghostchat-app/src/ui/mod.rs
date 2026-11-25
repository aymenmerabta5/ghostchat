//! GUI state and update loop. Worker events are applied in `events`, local
//! slash commands and safety actions live in `actions`, rendering in `view`
//! and `thread`.

mod actions;
mod alerts;
mod code;
mod composer;
mod debug_view;
mod diagnostics;
mod events;
mod files;
mod first_run;
mod geo_people;
mod location;
mod markup;
mod mesh_layout;
mod mesh_map;
mod native_icon;
mod panel;
mod saved;
mod slash;
mod thread;
mod tor_view;
mod tray;
mod verify_view;
mod view;

use crate::inbox::{Conversation, Inbox};
use crate::mesh_worker::{self, Command, MeshHandle};
use crate::recorder::VoiceRecorder;
use crate::roster::Roster;
use crate::social::Social;
use crate::theme;
use crate::voice::VoicePlayer;
use anyhow::Result;
use composer::focus_composer;
use files::SlashKey;
use ghostchat_nostr::Transport;
use iced::widget::{container, text_editor};
use iced::{window, Font, Subscription, Task};
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Fallback window icon; `native_icon` swaps in the exe's `.ico` frames.
const WINDOW_ICON: &[u8] = include_bytes!("../../../../assets/ghostchat-256.png");

pub fn run_gui(radio: mesh_worker::Radio, nickname: Option<String>, background: bool) -> Result<()> {
    crate::update::cleanup();
    let icon = window::icon::from_file_data(WINDOW_ICON, None)
        .map_err(|err| tracing::warn!(%err, "window icon unreadable"))
        .ok();
    iced::application("ghostchat", App::update, App::view)
        .subscription(App::subscription)
        .theme(|_| theme::application())
        .default_font(Font::MONOSPACE)
        .window(window::Settings {
            size: iced::Size::new(1100.0, 720.0),
            icon,
            visible: !background,
            exit_on_close_request: false,
            ..window::Settings::default()
        })
        .run_with(move || App::new(radio, nickname.clone(), background))
        .map_err(|err| anyhow::anyhow!("{err}"))
}

struct App {
    handle: Option<MeshHandle>,
    /// The route relays use; update checks take the same one.
    transport: Transport,
    nickname: String,
    nick_draft: String,
    peer_id: String,
    fingerprint: String,
    npub: String,
    status: String,
    draft: String,
    /// Half-typed lines of the other chats, stashed when the user switches.
    drafts: HashMap<Conversation, String>,
    /// Multi-line editor backing `draft` (pasted code keeps its newlines).
    composer: text_editor::Content,
    inbox: Inbox,
    roster: Roster,
    social: Social,
    /// `None` when the store could not be read; we then never overwrite it.
    social_path: Option<PathBuf>,
    /// Location channels the worker confirmed joined.
    joined: BTreeSet<String>,
    linking: Vec<(String, Instant)>,
    error: Option<String>,
    /// The chat `error` belongs to; `None` means it concerns the app itself
    /// (radio, storage) and is shown everywhere.
    error_conv: Option<Conversation>,
    radio_ready: bool,
    /// Bluetooth is stuck; the header offers "reset Bluetooth".
    offer_reset: bool,
    /// The worker reset the radio; start a fresh ghostchat and exit.
    relaunching: bool,
    /// `None` until Bluetooth starts (or when there is no adapter).
    advertising: Option<bool>,
    selected: Conversation,
    /// Messages are being picked for copying; the composer steps aside.
    select_mode: bool,
    selected_lines: BTreeSet<String>,
    /// Last plain click in select mode, for shift-click ranges.
    select_anchor: Option<String>,
    shift_held: bool,
    show_fingerprint: bool,
    /// The open group's roster panel is showing.
    show_group_members: bool,
    /// Recent clicks on the title; three quickly = panic wipe.
    title_clicks: Vec<Instant>,
    /// A file is being dragged over the window.
    drop_hover: bool,
    voice: VoicePlayer,
    recorder: VoiceRecorder,
    /// Where the note being recorded goes (fixed when recording starts).
    record_target: Option<Conversation>,
    /// Peers streaming push-to-talk to us, since when.
    talking: HashMap<String, Instant>,
    /// Peers streaming push-to-talk to everyone in `#mesh`.
    mesh_talking: HashMap<String, Instant>,
    /// Highlighted row in the command suggestions.
    slash_pick: usize,
    history: saved::SavedHistory,
    panel: panel::PanelState,
    location: location::LocationState,
    /// When `status` last changed; routine notes fade after a while.
    status_seen: (String, Instant),
    alone: first_run::Alone,
    /// Where each peer's `/ping` or `/trace` reply goes.
    diag_replies: HashMap<String, Conversation>,
    /// Toasts, tray icon and window visibility.
    background: alerts::Background,
    /// Groups the worker reports, for the sidebar and member panel.
    groups: Vec<crate::groups::GroupSummary>,
}

/// Routine status notes ("scan started", "wiped") hide after this; errors stay.
const STATUS_TTL: Duration = Duration::from_secs(10);
/// Housekeeping only: worker events, tray and toast clicks wake the GUI
/// themselves (see `wake`).
const IDLE_TICK: Duration = Duration::from_secs(1);
/// Voice playback, recording and the QR camera are polled.
const BUSY_TICK: Duration = Duration::from_millis(200);

/// iOS caps a burst at 120 s; a talker that vanished without END is stale.
const TALKING_TIMEOUT: Duration = Duration::from_secs(125);

/// Wrapper id used by the custom focus operation (`text_editor` has no id of
/// its own in iced 0.13).
fn composer_container_id() -> container::Id {
    container::Id::new("composer")
}

/// `Content::text` appends a synthetic newline to its last line; rebuilding
/// from the editor's lines keeps the draft exactly what the user typed.
fn editor_text(content: &text_editor::Content) -> String {
    let mut text = String::new();
    for (i, line) in content.lines().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        text.push_str(&line);
    }
    text
}

/// iced has no blur event, so a click or keystroke elsewhere stands in for
/// iOS saving the nickname when its field loses focus.
fn leaves_nick_field(message: &Message) -> bool {
    matches!(
        message,
        Message::DraftChanged(_)
            | Message::Submit
            | Message::Select(_)
            | Message::OpenUnread
            | Message::TitleClicked
            | Message::PickFile
            | Message::RecordStart
            | Message::ToggleFavorite(_)
            | Message::ToggleFingerprint
            | Message::ToggleGroupMembers
            | Message::GroupInvite(_)
            | Message::GroupRemove(_)
            | Message::GroupLeave
            | Message::Compose(_)
            | Message::JoinGeohash(_)
            | Message::ToggleSelectMode
            | Message::SelectLine(_)
            | Message::SelectAll
            | Message::CopySelected
            | Message::CopyText(_)
            | Message::Location(location::LocMsg::Open)
    )
}

#[derive(Debug, Clone)]
enum Message {
    Tick,
    /// An edit or cursor move in the multi-line composer.
    DraftChanged(text_editor::Action),
    Submit,
    NickChanged(String),
    NickSubmit,
    Select(Conversation),
    OpenUnread,
    /// Enter or leave message-picking mode.
    ToggleSelectMode,
    /// Pick one message (shift-click extends from the anchor).
    SelectLine(String),
    SelectAll,
    CopySelected,
    /// Write text (a code block, usually) to the clipboard.
    CopyText(String),
    /// Shift is held, for shift-click range selection.
    ShiftChanged(bool),
    /// Escape leaves select mode.
    CancelSelection,
    ToggleFavorite(String),
    ToggleVerified(String),
    ToggleFingerprint,
    /// Show or hide the open group's roster panel.
    ToggleGroupMembers,
    /// Invite this nickname to the open group.
    GroupInvite(String),
    /// Remove this nickname from the open group we created.
    GroupRemove(String),
    /// Leave the open group (local only).
    GroupLeave,
    /// Put a command stub in the composer (sidebar "new group").
    Compose(String),
    LeaveGeo(String),
    TitleClicked,
    /// Open a saved image or file with its default Windows app.
    OpenPath(PathBuf),
    /// Show a saved file selected in Explorer.
    RevealPath(PathBuf),
    PlayVoice(PathBuf),
    PickFile,
    FilePicked(Option<PathBuf>),
    DropHover(bool),
    FileDropped(PathBuf),
    /// A command suggestion was clicked.
    SlashChosen(usize),
    SlashKey(SlashKey),
    RecordStart,
    /// Stop recording; `true` sends the note, `false` discards it.
    RecordFinish(bool),
    /// A `#geohash` tag in a message was clicked.
    JoinGeohash(String),
    /// An http(s) link in a message was clicked.
    OpenUrl(String),
    /// A Cashu or Lightning chip was clicked (`cashu:` / `lightning:`).
    OpenPayment(String),
    Panel(panel::PanelMsg),
    Debug(debug_view::DebugMsg),
    /// Turn Bluetooth off and on, then restart ghostchat.
    ResetBluetooth,
    Location(location::LocMsg),
    CloseRequested(window::Id),
    Focus(bool),
}

impl App {
    fn new(radio: mesh_worker::Radio, nickname: Option<String>, background: bool) -> (Self, Task<Message>) {
        // Settings first: the worker must know the relay route before it
        // connects to any relay.
        let (social, social_path, social_error) = load_social();
        let (transport, tor_error) = match Transport::from_setting(social.tor_proxy.as_deref()) {
            Ok(t) => (t, None),
            Err(err) => (Transport::Direct, Some(format!("tor setting ignored: {err}"))),
        };
        let (handle, boot_error) = match mesh_worker::spawn(radio, nickname, transport) {
            Ok(handle) => (Some(handle), None),
            Err(err) => (None, Some(err.to_string())),
        };
        let error = boot_error.or(social_error).or(tor_error);
        let mut app = Self {
            handle,
            transport,
            nickname: String::new(),
            nick_draft: String::new(),
            peer_id: String::new(),
            fingerprint: String::new(),
            npub: String::new(),
            status: error.clone().unwrap_or_else(|| "starting mesh…".into()),
            draft: String::new(),
            drafts: HashMap::new(),
            composer: text_editor::Content::new(),
            inbox: Inbox::default(),
            roster: Roster::default(),
            social,
            social_path,
            joined: BTreeSet::new(),
            linking: Vec::new(),
            error,
            // Boot errors (storage, Tor setting) concern the app, not a chat.
            error_conv: None,
            radio_ready: false,
            offer_reset: false,
            relaunching: false,
            advertising: None,
            selected: Conversation::Mesh,
            select_mode: false,
            selected_lines: BTreeSet::new(),
            select_anchor: None,
            shift_held: false,
            show_fingerprint: false,
            show_group_members: false,
            title_clicks: Vec::new(),
            drop_hover: false,
            voice: VoicePlayer::default(),
            recorder: VoiceRecorder::default(),
            record_target: None,
            talking: HashMap::new(),
            mesh_talking: HashMap::new(),
            slash_pick: 0,
            history: saved::SavedHistory::default(),
            panel: panel::PanelState::default(),
            location: location::LocationState::default(),
            status_seen: (String::new(), Instant::now()),
            alone: first_run::Alone::default(),
            diag_replies: HashMap::new(),
            background: alerts::Background::new(),
            groups: Vec::new(),
        };
        app.restore_social();
        app.restore_history();
        let icons = window::get_latest().and_then(|id| window::run_with_handle(id, native_icon::apply)).discard();
        // Presence heartbeats wait for a fix; without one phones never count us.
        let locate = if app.social.location_enabled { app.start_locating() } else { Task::none() };
        let start = app.start_hidden(background);
        // A quiet check after the window is up; a failure stays silent, and
        // the settings sheet can always ask again.
        let update = Task::perform(
            async move {
                tokio::time::sleep(Duration::from_secs(4)).await;
                crate::update::check(transport).await
            },
            |result| Message::Panel(panel::PanelMsg::Update(panel::UpdateMsg::Checked { manual: false, result })),
        );
        (app, Task::batch([icons, locate, start, focus_composer(), update]))
    }

    /// Offline roster rows for saved contacts, the Nostr contact list for
    /// the worker, and the location channels to rejoin.
    fn restore_social(&mut self) {
        for contact in self.social.contacts.values() {
            if contact.peer_id.is_empty() || self.social.is_blocked(&contact.fingerprint) {
                continue;
            }
            self.roster.known(&contact.peer_id, &contact.nick);
            self.roster.set_fingerprint(&contact.peer_id, contact.fingerprint.clone());
        }
        self.push_contacts();
        for cell in self.social.geohashes.clone() {
            self.joined.insert(cell.clone());
            self.send(Command::JoinGeo(cell));
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        if leaves_nick_field(&message) {
            self.commit_nick_draft();
        }
        match message {
            Message::Tick => {
                self.voice.poll();
                self.poll_recorder();
                self.talking.retain(|_, since| since.elapsed() < TALKING_TIMEOUT);
                self.mesh_talking.retain(|_, since| since.elapsed() < TALKING_TIMEOUT);
                let alert = self.drain_events();
                if self.relaunching {
                    return self.relaunch();
                }
                if self.status_seen.0 != self.status {
                    self.status_seen = (self.status.clone(), Instant::now());
                }
                self.alone.update(self.radio_ready && self.roster.online_peers().next().is_none(), Instant::now());
                self.persist_history();
                self.refresh_my_qr(self.panel.tab == Some(panel::Tab::Settings));
                let background = self.background_tick();
                let copy = self.take_report_copy();
                if alert && !self.background.hidden {
                    return Task::batch([background, copy, flash_taskbar()]);
                }
                return Task::batch([background, copy]);
            }
            Message::CloseRequested(id) => return self.on_close_requested(id),
            Message::ResetBluetooth => {
                self.offer_reset = false;
                self.send(Command::ResetBluetooth);
            }
            Message::Focus(on) => {
                self.background.focused = on;
                // Shift released outside the window never sends its own event.
                if !on {
                    self.shift_held = false;
                }
            }
            Message::DraftChanged(action) => {
                let edited = action.is_edit();
                self.composer.perform(action);
                if edited {
                    self.draft = editor_text(&self.composer);
                    self.slash_pick = 0;
                }
            }
            Message::Submit => {
                // Enter on a half-typed command takes the highlighted suggestion.
                if !self.slash_suggestions().is_empty() {
                    let needs_args = self.accept_suggestion(self.slash_pick);
                    if needs_args {
                        return focus_composer();
                    }
                }
                let line = self.draft.trim_end().to_string();
                if !line.starts_with('/') && line.len() > ghostchat_protocol::message::MAX_CONTENT_BYTES {
                    self.set_error(
                        "message is over the 64 KiB mesh limit - split it, or send it as a .txt/.ipynb attachment"
                            .into(),
                    );
                    return focus_composer();
                }
                self.clear_composer();
                if !self.run_local(&line) {
                    match self.command_for(&line) {
                        Some(cmd) => self.send(cmd),
                        None if line.starts_with('/') => {
                            self.set_error(format!("unknown command {line:?}; type /help"))
                        }
                        None => {}
                    }
                }
                return focus_composer();
            }
            Message::ToggleSelectMode => {
                self.toggle_select_mode();
                return if self.select_mode { Task::none() } else { focus_composer() };
            }
            Message::SelectLine(id) => self.select_line(&id),
            Message::SelectAll => self.select_all(),
            Message::CopySelected => {
                if !self.select_mode {
                    return Task::none();
                }
                let (text, count) = self.selected_text();
                if count > 0 {
                    self.status = format!("copied {count} message{}", if count == 1 { "" } else { "s" });
                    self.status_seen = (self.status.clone(), Instant::now());
                    return iced::clipboard::write(text);
                }
            }
            Message::CopyText(text) => {
                self.status = "code copied to clipboard".into();
                self.status_seen = (self.status.clone(), Instant::now());
                return iced::clipboard::write(text);
            }
            Message::ShiftChanged(held) => self.shift_held = held,
            Message::CancelSelection => {
                if self.select_mode {
                    self.exit_select_mode();
                    return focus_composer();
                }
            }
            Message::NickChanged(value) => self.nick_draft = value,
            Message::NickSubmit => self.commit_nick_draft(),
            Message::Select(conv) => self.select(conv),
            Message::OpenUnread => {
                let next = self
                    .roster
                    .online_peers()
                    .chain(self.roster.offline_peers())
                    .map(|p| Conversation::Dm(p.id.clone()))
                    .find(|c| self.inbox.unread(c) > 0);
                if let Some(conv) = next {
                    self.select(conv);
                }
            }
            Message::ToggleFavorite(id) => {
                let on = !self.fingerprint_of(&id).is_some_and(|fp| self.social.is_favorite(&fp));
                self.send(Command::Favorite { to: id, on });
            }
            Message::ToggleVerified(id) => match self.fingerprint_of(&id) {
                Some(fp) => {
                    let on = !self.social.is_verified(&fp);
                    Social::set(&mut self.social.verified, &fp, on);
                    self.save_social();
                }
                None => self.set_error("fingerprint unknown until the peer announces".into()),
            },
            Message::ToggleFingerprint => self.show_fingerprint = !self.show_fingerprint,
            Message::ToggleGroupMembers => self.show_group_members = !self.show_group_members,
            Message::GroupInvite(nick) => self.send(Command::GroupInvite(nick)),
            Message::GroupRemove(nick) => self.send(Command::GroupRemove(nick)),
            Message::GroupLeave => {
                self.send(Command::GroupLeave);
                self.show_group_members = false;
            }
            Message::Compose(text) => {
                self.draft = text;
                self.slash_pick = 0;
                self.replace_composer();
                return focus_composer();
            }
            Message::LeaveGeo(cell) => self.leave_geo(&cell),
            Message::OpenPath(path) => {
                if let Some(err) = files::open_path(&path) {
                    self.set_error(err);
                }
            }
            Message::RevealPath(path) => {
                if let Some(err) = files::reveal_path(&path) {
                    self.set_error(err);
                }
            }
            Message::PlayVoice(path) => self.toggle_voice(&path),
            Message::PickFile => return self.pick_file(),
            Message::FilePicked(Some(path)) => self.send_file(&path.to_string_lossy(), false),
            Message::FilePicked(None) => {}
            Message::DropHover(on) => self.drop_hover = on,
            Message::FileDropped(path) => self.on_dropped(path),
            Message::SlashChosen(index) => {
                self.accept_suggestion(index);
                return focus_composer();
            }
            Message::SlashKey(key) => return self.on_slash_key(key),
            Message::RecordStart => self.start_recording(),
            Message::RecordFinish(keep) => self.recorder.finish(keep),
            Message::JoinGeohash(cell) => self.join_geo(cell),
            Message::OpenUrl(url) => {
                if let Some(err) = files::open_url(&url) {
                    self.set_error(err);
                }
            }
            Message::OpenPayment(url) => {
                if let Some(err) = files::open_payment(&url) {
                    self.set_error(err);
                }
            }
            // One click opens settings; three quick clicks ask to wipe (iOS).
            Message::TitleClicked => {
                let now = Instant::now();
                self.title_clicks.retain(|t| now.duration_since(*t) < Duration::from_millis(1500));
                self.title_clicks.push(now);
                self.close_sheet();
                self.set_panel_tab(Some(panel::Tab::Settings));
                if self.title_clicks.len() >= 3 {
                    self.title_clicks.clear();
                    self.panel.confirm_wipe = true;
                }
            }
            Message::Panel(msg) => return self.on_panel(msg),
            Message::Debug(msg) => self.on_debug(msg),
            Message::Location(msg) => return self.on_location(msg),
        }
        Task::none()
    }

    /// Save an edited nickname; a blank one rolls a new `anon####`.
    fn commit_nick_draft(&mut self) {
        let nick = self.nick_draft.trim().to_string();
        if nick == self.nickname {
            return;
        }
        self.send(Command::SetNick(nick.clone()));
        // Settle now so the next commit does not resend (a blank would roll
        // a second name); the worker's `Me` event brings the final name.
        if nick.is_empty() {
            self.nick_draft = self.nickname.clone();
        } else {
            self.nickname = nick;
        }
    }

    fn select(&mut self, conv: Conversation) {
        if let Conversation::Dm(id) = &conv {
            self.send(Command::OpenDm(id.clone()));
        }
        if let Conversation::Group(id) = &conv {
            self.send(Command::GroupFocus(id.clone()));
        }
        if conv != self.selected {
            self.show_fingerprint = false;
            // Keep what was typed per chat: switching to read another
            // conversation must not discard a half-written line, and the
            // next chat must not open with the previous one's text.
            let outgoing = self.selected.clone();
            if self.draft.is_empty() {
                self.drafts.remove(&outgoing);
            } else {
                self.drafts.insert(outgoing, std::mem::take(&mut self.draft));
            }
            self.draft = self.drafts.remove(&conv).unwrap_or_default();
            self.replace_composer();
            // An error about one chat should not sit in the next chat's
            // header. Errors about the app itself (radio, storage) stay.
            if self.error_conv.take().is_some() {
                self.error = None;
                self.status.clear();
            }
        }
        self.exit_select_mode();
        self.set_panel_tab(None);
        self.panel.confirm_wipe = false;
        self.close_sheet();
        self.selected = conv;
        self.inbox.open(&self.selected);
        self.send_read_receipts();
    }

    /// Put `draft` back into the multi-line editor, cursor at the end.
    fn replace_composer(&mut self) {
        self.composer = text_editor::Content::with_text(&self.draft);
        self.composer.perform(text_editor::Action::Move(text_editor::Motion::End));
    }

    fn clear_composer(&mut self) {
        self.draft.clear();
        self.composer = text_editor::Content::new();
    }

    fn exit_select_mode(&mut self) {
        self.select_mode = false;
        self.selected_lines.clear();
        self.select_anchor = None;
    }

    fn toggle_select_mode(&mut self) {
        self.select_mode = !self.select_mode;
        self.selected_lines.clear();
        self.select_anchor = None;
    }

    /// Toggle one message, or extend from the last plain click with Shift.
    fn select_line(&mut self, id: &str) {
        if !self.select_mode || id.is_empty() {
            return;
        }
        let visible: Vec<String> = self
            .inbox
            .visible(&self.selected)
            .into_iter()
            .filter(|entry| !entry.system && !entry.line.id.is_empty())
            .map(|entry| entry.line.id.clone())
            .collect();
        if self.shift_held {
            if let Some(anchor) = self.select_anchor.as_deref() {
                let a = visible.iter().position(|line| line == anchor);
                let b = visible.iter().position(|line| line == id);
                if let (Some(a), Some(b)) = (a, b) {
                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                    self.selected_lines.clear();
                    self.selected_lines.extend(visible[lo..=hi].iter().cloned());
                    return;
                }
            }
        }
        if !self.selected_lines.remove(id) {
            self.selected_lines.insert(id.to_string());
        }
        self.select_anchor = Some(id.to_string());
    }

    fn select_all(&mut self) {
        self.selected_lines = self
            .inbox
            .visible(&self.selected)
            .into_iter()
            .filter(|entry| !entry.system && !entry.line.id.is_empty())
            .map(|entry| entry.line.id.clone())
            .collect();
        self.select_anchor = None;
    }

    /// How many picked messages would actually contribute text to the
    /// clipboard, matching [`Self::selected_text`].
    fn selected_count(&self) -> usize {
        self.inbox
            .visible(&self.selected)
            .into_iter()
            .filter(|entry| !entry.system && self.selected_lines.contains(&entry.line.id))
            .filter(|entry| !entry.line.content.is_empty())
            .count()
    }

    /// Selected bodies in thread order, and how many actually had text.
    fn selected_text(&self) -> (String, usize) {
        let bodies: Vec<&str> = self
            .inbox
            .visible(&self.selected)
            .into_iter()
            .filter(|entry| !entry.system && self.selected_lines.contains(&entry.line.id))
            .map(|entry| entry.line.content.as_str())
            .filter(|body| !body.is_empty())
            .collect();
        (bodies.join("\n\n"), bodies.len())
    }

    fn send(&self, cmd: Command) {
        if let Some(handle) = &self.handle {
            let _ = handle.tx.send(cmd);
        }
    }

    pub(super) fn group_summary(&self, id: &str) -> Option<&crate::groups::GroupSummary> {
        self.groups.iter().find(|g| g.id == id)
    }

    fn push_contacts(&self) {
        let mut contacts = self.social.reachable_contacts();
        contacts.extend(
            self.social
                .contacts
                .values()
                .filter(|c| c.npub.is_none() && self.social.is_favorite(&c.fingerprint))
                .cloned(),
        );
        self.send(Command::Contacts(contacts));
        self.send(Command::Blocked(self.social.blocked.iter().cloned().collect()));
        self.send(Command::CourierFavorites(self.social.mutual_favorites()));
        self.send(Command::Relays(self.social.relays.clone()));
        self.send(Command::StayAwake(self.social.stay_awake));
    }

    fn send_read_receipts(&mut self) {
        let peer = match &self.selected {
            Conversation::Dm(peer) => peer.clone(),
            Conversation::GeoDm { pubkey, .. } => pubkey.clone(),
            _ => return,
        };
        for message_id in self.inbox.take_unreceipted(&self.selected) {
            self.send(Command::MarkRead { peer: peer.clone(), message_id });
        }
    }

    /// Apply worker events. Returns true when the user should be alerted.
    fn drain_events(&mut self) -> bool {
        let Some(handle) = &self.handle else {
            return false;
        };
        let events: Vec<_> = handle.rx.try_iter().collect();
        self.linking.retain(|(_, seen)| seen.elapsed() < Duration::from_secs(20));
        let mut alert = false;
        for event in events {
            alert |= self.apply(event);
        }
        self.send_read_receipts();
        alert
    }

    fn save_social(&mut self) {
        let Some(path) = &self.social_path else {
            return;
        };
        if let Err(err) = self.social.save(path) {
            self.set_app_error(format!("could not save favorites: {err}"));
        }
    }

    /// An error about the chat the user is looking at: it clears when they
    /// move to another chat, and is not repeated there.
    fn set_error(&mut self, err: String) {
        self.error = Some(err.clone());
        self.error_conv = Some(self.selected.clone());
        self.status = err;
    }

    /// An error about the app itself (radio, storage): it stays until the
    /// condition clears, whichever chat is open.
    fn set_app_error(&mut self, err: String) {
        self.error = Some(err.clone());
        self.error_conv = None;
        self.status = err;
    }

    fn subscription(&self) -> Subscription<Message> {
        let busy = self.voice.is_playing() || self.recorder.is_active() || self.panel.verify.camera_running();
        Subscription::batch([
            iced::time::every(if busy { BUSY_TICK } else { IDLE_TICK }).map(|_| Message::Tick),
            Subscription::run(crate::wake::wakes).map(|()| Message::Tick),
            files::window_events(),
            window::close_requests().map(Message::CloseRequested),
        ])
    }

    fn display_name(&self, id: &str) -> String {
        self.roster.display_name(id, &self.peer_id, &self.nickname)
    }

    /// A peer's line label, collision-suffixed like the sidebar. Location
    /// lines already arrive as `nick#abcd` and carry no peer id.
    fn sender_name(&self, line: &ghostchat_core::ChatLine) -> String {
        match &line.peer_id {
            Some(peer) if self.roster.get(&peer.hex).is_some() => self.display_name(&peer.hex),
            _ => line.from.clone(),
        }
    }

    /// The `@name` that means us: suffixed while a mesh peer shares our nick
    /// (iOS `checkForMentions` uses this token in every channel).
    fn mention_name(&self) -> String {
        self.roster.self_display_name(&self.peer_id, &self.nickname)
    }

    fn fingerprint_of(&self, id: &str) -> Option<String> {
        self.roster.get(id).and_then(|p| p.fingerprint.clone())
    }

    fn unread_dms(&self) -> usize {
        self.roster
            .online_peers()
            .chain(self.roster.offline_peers())
            .map(|p| self.inbox.unread(&Conversation::Dm(p.id.clone())))
            .sum()
    }
}

fn load_social() -> (Social, Option<PathBuf>, Option<String>) {
    let Some(path) = Social::default_path() else {
        return (Social::default(), None, Some("no data directory; favorites not saved".into()));
    };
    match Social::load(&path) {
        Ok(social) => {
            let locked = social.locked().then(|| {
                "favorites, contacts and channels are locked: the keyring did not open them; \
                 they stay unchanged this session"
                    .to_string()
            });
            (social, Some(path), locked)
        }
        Err(err) => (Social::default(), None, Some(format!("favorites not loaded: {err:#}"))),
    }
}

/// Flash the taskbar button until the window is focused (no-op when focused).
fn flash_taskbar() -> Task<Message> {
    window::get_latest().and_then(|id| window::request_user_attention(id, Some(window::UserAttention::Informational)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composer_text_matches_what_was_typed() {
        assert_eq!(editor_text(&text_editor::Content::with_text("")), "");
        assert_eq!(editor_text(&text_editor::Content::with_text("one line")), "one line");
        assert_eq!(editor_text(&text_editor::Content::with_text("one\ntwo")), "one\ntwo");
        // `Content` normalizes away one trailing line break.
        assert_eq!(editor_text(&text_editor::Content::with_text("trailing\n")), "trailing");
    }
}
