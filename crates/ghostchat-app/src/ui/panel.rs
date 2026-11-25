//! The app info sheet, opened by clicking `ghostchat/` (iOS: tapping
//! `bitchat/`). `settings`: identity, voice, history, private-message
//! relays and the panic wipe. `info`: features, symbols, privacy, how to use.

use super::view::{MONO, SANS, SANS_BOLD, SANS_SEMIBOLD, SYMBOL};
use super::{App, Message};
use crate::theme;
use crate::update::{self, Phase};
use ghostchat_nostr::{add_custom_relay, DM_RELAYS};
use iced::widget::{button, column, container, row, scrollable, text, text_input, Space};
use iced::{Alignment, Element, Length, Task};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Tab {
    Settings,
    Debug,
    Info,
}

#[derive(Debug, Clone)]
pub(super) enum PanelMsg {
    Open(Tab),
    Close,
    ToggleHistory,
    ToggleNotifications,
    ToggleBackground,
    ToggleAutostart,
    ToggleStayAwake,
    RelayDraft(String),
    RelayAdd,
    RelayRemove(String),
    /// Show (true) or dismiss the wipe confirmation.
    AskWipe(bool),
    WipeNow,
    Copy(String),
    Verify(super::verify_view::VerifyMsg),
    Tor(super::tor_view::TorMsg),
    Update(UpdateMsg),
}

/// The update row in settings: check, download, install and restart.
#[derive(Debug, Clone)]
pub(super) enum UpdateMsg {
    Check,
    Checked { manual: bool, result: Result<Option<update::Release>, String> },
    Install,
    Staged(Result<PathBuf, String>),
    Installed(Result<PathBuf, String>),
}

/// Panel state kept on `App`.
#[derive(Default)]
pub(super) struct PanelState {
    pub tab: Option<Tab>,
    pub confirm_wipe: bool,
    relay_draft: String,
    relay_error: Option<String>,
    pub verify: super::verify_view::VerifyState,
    pub tor: super::tor_view::TorState,
    pub debug: super::debug_view::DebugState,
    pub update: update::State,
}

impl App {
    pub(super) fn on_panel(&mut self, msg: PanelMsg) -> Task<Message> {
        match msg {
            PanelMsg::Open(tab) => {
                self.close_sheet();
                self.set_panel_tab(Some(tab));
            }
            PanelMsg::Close => {
                self.set_panel_tab(None);
                self.panel.confirm_wipe = false;
            }
            PanelMsg::ToggleHistory => {
                let next = if self.social.keep_history { "off" } else { "on" };
                self.set_history(next);
            }
            PanelMsg::ToggleNotifications => {
                self.social.notifications_off = !self.social.notifications_off;
                self.save_social();
            }
            PanelMsg::ToggleBackground => {
                self.social.quit_on_close = !self.social.quit_on_close;
                self.save_social();
            }
            PanelMsg::ToggleAutostart => self.toggle_autostart(),
            PanelMsg::ToggleStayAwake => {
                self.social.stay_awake = !self.social.stay_awake;
                self.save_social();
                self.send(crate::mesh_worker::Command::StayAwake(self.social.stay_awake));
            }
            PanelMsg::RelayDraft(value) => {
                self.panel.relay_draft = value;
                self.panel.relay_error = None;
            }
            PanelMsg::RelayAdd => {
                let draft = std::mem::take(&mut self.panel.relay_draft);
                let tor = self.tor_on();
                match add_custom_relay(&mut self.social.relays, &draft, DM_RELAYS, tor) {
                    Ok(_) => self.relays_changed(),
                    Err(err) => {
                        self.panel.relay_draft = draft;
                        self.panel.relay_error = Some(err.to_string());
                    }
                }
            }
            PanelMsg::RelayRemove(url) => {
                self.social.relays.retain(|r| *r != url);
                self.relays_changed();
            }
            PanelMsg::AskWipe(on) => self.panel.confirm_wipe = on,
            PanelMsg::WipeNow => {
                // Drops our QR too: it names the identity being wiped.
                self.set_panel_tab(None);
                self.panel = PanelState::default();
                self.panic_wipe();
            }
            PanelMsg::Copy(value) => return iced::clipboard::write(value),
            PanelMsg::Verify(msg) => return self.on_verify(msg),
            PanelMsg::Tor(msg) => self.on_tor(msg),
            PanelMsg::Update(msg) => return self.on_update(msg),
        }
        Task::none()
    }

    fn on_update(&mut self, msg: UpdateMsg) -> Task<Message> {
        match msg {
            UpdateMsg::Check => {
                self.panel.update.phase = Phase::Checking;
                self.panel.update.error = None;
                let transport = self.transport;
                Task::perform(update::check(transport), |result| {
                    Message::Panel(PanelMsg::Update(UpdateMsg::Checked { manual: true, result }))
                })
            }
            UpdateMsg::Checked { manual, result } => {
                // A late answer from the startup check must not reset a
                // download that has already begun.
                if matches!(self.panel.update.phase, Phase::Downloading | Phase::Ready) {
                    return Task::none();
                }
                let state = &mut self.panel.update;
                match result {
                    Ok(Some(release)) => {
                        // A staged build belongs to the release that was on
                        // offer; a different release needs its own download.
                        if state.latest.as_ref().is_some_and(|current| current.version != release.version) {
                            state.staged = None;
                        }
                        state.latest = Some(release);
                        state.phase = Phase::Available;
                        state.error = None;
                    }
                    Ok(None) => {
                        state.latest = None;
                        state.staged = None;
                        state.phase = Phase::UpToDate;
                        state.error = None;
                    }
                    Err(err) if manual => {
                        state.phase = Phase::Failed;
                        state.error = Some(err);
                    }
                    // The quiet startup check stays quiet when offline.
                    Err(_) => {
                        state.phase = Phase::Idle;
                        state.error = None;
                    }
                }
                Task::none()
            }
            UpdateMsg::Install => {
                if matches!(self.panel.update.phase, Phase::Downloading | Phase::Ready) {
                    return Task::none();
                }
                if let Some(staged) = self.panel.update.staged.clone() {
                    return self.apply_update(staged);
                }
                let Some(release) = self.panel.update.latest.clone() else {
                    // The last failure was the check itself; ask again.
                    return self.on_update(UpdateMsg::Check);
                };
                self.panel.update.phase = Phase::Downloading;
                self.panel.update.error = None;
                let transport = self.transport;
                Task::perform(async move { update::stage(&release, transport).await }, |result| {
                    Message::Panel(PanelMsg::Update(UpdateMsg::Staged(result)))
                })
            }
            UpdateMsg::Staged(result) => match result {
                Ok(staged) => {
                    self.panel.update.staged = Some(staged.clone());
                    self.apply_update(staged)
                }
                Err(err) => {
                    self.panel.update.phase = Phase::Failed;
                    self.panel.update.error = Some(err);
                    Task::none()
                }
            },
            UpdateMsg::Installed(result) => match result {
                Ok(exe) => match crate::relaunch::spawn_exe(&exe) {
                    Ok(()) => self.quit(),
                    Err(err) => {
                        let version = self
                            .panel
                            .update
                            .latest
                            .as_ref()
                            .map(|release| release.version.clone())
                            .unwrap_or_else(|| update::CURRENT.to_string());
                        let state = &mut self.panel.update;
                        // The executable is already replaced: another
                        // install would run against the old image, so offer
                        // a restart instead of a retry.
                        state.phase = Phase::Restart;
                        state.latest = None;
                        state.staged = None;
                        state.error = Some(format!(
                            "ghostchat {version} is installed, but it could not restart itself ({err}). Start it again."
                        ));
                        Task::none()
                    }
                },
                Err(err) => {
                    self.panel.update.phase = Phase::Failed;
                    self.panel.update.error = Some(err);
                    Task::none()
                }
            },
        }
    }

    /// Install a verified executable off the UI thread, then report back so
    /// the restart happens on the update loop.
    fn apply_update(&mut self, staged: PathBuf) -> Task<Message> {
        self.panel.update.phase = Phase::Ready;
        self.panel.update.error = None;
        Task::perform(async move { tokio::task::spawn_blocking(move || update::install(&staged)).await }, |result| {
            let result = match result {
                Ok(inner) => inner,
                Err(err) => Err(format!("the update could not finish: {err}")),
            };
            Message::Panel(PanelMsg::Update(UpdateMsg::Installed(result)))
        })
    }

    /// The worker streams debug snapshots only while that tab is shown.
    pub(super) fn set_panel_tab(&mut self, tab: Option<Tab>) {
        let was = self.panel.tab == Some(Tab::Debug);
        let now = tab == Some(Tab::Debug);
        self.panel.tab = tab;
        if was != now {
            self.send(crate::mesh_worker::Command::Diag(crate::worker_diag::DiagCommand::Watch(now)));
        }
    }

    fn relays_changed(&mut self) {
        self.save_social();
        self.send(crate::mesh_worker::Command::Relays(self.social.relays.clone()));
    }

    /// Shown instead of the conversation while the panel is open.
    pub(super) fn panel_view(&self, tab: Tab) -> Element<'_, Message> {
        let tab_button = |label: &'static str, which: Tab| {
            button(text(label).size(10.5).font(SANS))
                .on_press(Message::Panel(PanelMsg::Open(which)))
                .padding([5, 12])
                .style(theme::conv_button(tab == which))
        };
        let head = row![
            column![
                text("ghostchat").size(14).font(SANS_BOLD).color(theme::TEXT),
                text("bitchat-compatible mesh chat for the desktop").size(9.5).font(SANS).color(theme::MUTED),
            ]
            .spacing(3),
            Space::with_width(Length::Fill),
            tab_button("Settings", Tab::Settings),
            tab_button("Debug", Tab::Debug),
            tab_button("Info", Tab::Info),
            button(text("Done").size(10.5).font(SANS))
                .on_press(Message::Panel(PanelMsg::Close))
                .padding([5, 12])
                .style(theme::accent_button),
        ]
        .spacing(6)
        .align_y(Alignment::Center);
        let body = match tab {
            Tab::Settings => self.settings_tab(),
            Tab::Debug => self.debug_tab(),
            Tab::Info => info_tab(),
        };
        let body = container(body)
            .padding(iced::Padding { top: 8.0, right: 24.0, bottom: 32.0, left: 24.0 })
            .max_width(760)
            .width(Length::Fill);
        column![
            container(head).padding([12, 20]).width(Length::Fill).style(theme::header_bar),
            scrollable(container(body).width(Length::Fill).center_x(Length::Fill))
                .width(Length::Fill)
                .height(Length::Fill),
        ]
        .into()
    }

    fn settings_tab(&self) -> Element<'_, Message> {
        let mut items: Vec<Element<'_, Message>> = vec![heading("IDENTITY")];
        items.push(copy_row("nickname", format!("@{}", self.nickname), None));
        items.push(copy_row("peer id", self.peer_id.clone(), None));
        items.push(copy_row(
            "fingerprint",
            ghostchat_protocol::format_fingerprint(&self.fingerprint),
            Some(self.fingerprint.clone()),
        ));
        if !self.npub.is_empty() {
            items.push(copy_row("nostr", self.npub.clone(), Some(self.npub.clone())));
        }
        items.push(note(crate::key_protect::Protection::current().describe()));
        items.push(heading("UPDATES"));
        items.extend(self.update_section());
        items.push(heading("VERIFY"));
        items.extend(self.verify_section());
        items.push(heading("VOICE"));
        items.push(setting(
            "auto-play incoming voice: off",
            "voice notes and push-to-talk never play by themselves; click ▶ to listen. an on/off switch may come later.",
            None,
        ));

        items.push(heading("NOTIFICATIONS"));
        items.extend(self.background_section());

        items.push(heading("PRIVACY"));
        let history = if self.social.keep_history { "on" } else { "off" };
        items.push(setting(
            "save channel history",
            "keeps #mesh and location-channel lines across restarts, as plaintext on this PC. private messages are never saved; one you sent that has not arrived waits encrypted for up to 24 h, then is dropped.",
            Some(toggle(history, Message::Panel(PanelMsg::ToggleHistory))),
        ));

        items.push(heading("TOR"));
        items.extend(self.tor_section());

        items.push(heading("PRIVATE MESSAGE RELAYS"));
        items.push(note(
            "when the mesh can't reach a mutual favorite, private messages travel through these relays. \
             the built-in ones are well-known addresses that a network filter can block, so you can add your own.",
        ));
        for relay in DM_RELAYS {
            items.push(relay_row(relay, None));
        }
        for relay in &self.social.relays {
            items.push(relay_row(relay, Some(Message::Panel(PanelMsg::RelayRemove(relay.clone())))));
        }
        items.push(
            row![
                text_input("wss://relay.example.com", &self.panel.relay_draft)
                    .on_input(|v| Message::Panel(PanelMsg::RelayDraft(v)))
                    .on_submit(Message::Panel(PanelMsg::RelayAdd))
                    .size(11)
                    .font(MONO)
                    .padding([5, 8])
                    .style(theme::composer),
                button(text("Add").size(10.5).font(SANS))
                    .on_press(Message::Panel(PanelMsg::RelayAdd))
                    .padding([5, 12])
                    .style(theme::accent_button),
            ]
            .spacing(8)
            .into(),
        );
        if let Some(err) = &self.panel.relay_error {
            items.push(text(err.clone()).size(12).color(theme::WARN).into());
        }

        items.push(heading("DANGER ZONE"));
        let wipe: Element<'_, Message> = if self.panel.confirm_wipe {
            row![
                text("Wipe identity, chats, and peers?").size(12).font(SANS_SEMIBOLD).color(theme::ALERT),
                button(text("Wipe").size(10.5).font(SANS_BOLD))
                    .on_press(Message::Panel(PanelMsg::WipeNow))
                    .padding([5, 12])
                    .style(theme::accent_button),
                button(text("Cancel").size(10.5).font(SANS))
                    .on_press(Message::Panel(PanelMsg::AskWipe(false)))
                    .padding([5, 12])
                    .style(theme::accent_button),
            ]
            .spacing(10)
            .align_y(Alignment::Center)
            .into()
        } else {
            button(text("Panic wipe").size(10.5).font(SANS).color(theme::ALERT))
                .on_press(Message::Panel(PanelMsg::AskWipe(true)))
                .padding([5, 12])
                .style(theme::accent_button)
                .into()
        };
        items.push(wipe);
        items.push(note(
            "erases all messages, keys, favorites, relays and identity. triple-clicking the ghostchat/ title does the same (asks to confirm).",
        ));
        column(items).spacing(8).into()
    }

    fn update_section(&self) -> Vec<Element<'_, Message>> {
        let state = &self.panel.update;
        let check = || {
            button(text("Check").size(10.5).font(SANS))
                .on_press(Message::Panel(PanelMsg::Update(UpdateMsg::Check)))
                .padding([5, 12])
                .style(theme::accent_button)
                .into()
        };
        match state.phase {
            Phase::Idle => vec![setting(
                format!("ghostchat {}", update::CURRENT),
                "check GitHub Releases for a newer version.",
                Some(check()),
            )],
            Phase::Checking => vec![note("checking GitHub Releases…")],
            Phase::UpToDate => {
                vec![setting(format!("ghostchat {}", update::CURRENT), "you are on the latest release.", Some(check()))]
            }
            Phase::Available => {
                let release = state.latest.as_ref().expect("an available update has a release");
                let actions: Element<'_, Message> = row![
                    button(text("Release notes").size(10.5).font(SANS))
                        .on_press(Message::OpenUrl(release.page.clone()))
                        .padding([5, 12])
                        .style(theme::accent_button),
                    button(text("Update").size(10.5).font(SANS_BOLD))
                        .on_press(Message::Panel(PanelMsg::Update(UpdateMsg::Install)))
                        .padding([5, 12])
                        .style(theme::accent_button),
                ]
                .spacing(8)
                .into();
                vec![setting(
                    format!("ghostchat {} is available", release.version),
                    "downloads the release, checks its SHA-256, and restarts ghostchat.",
                    Some(actions),
                )]
            }
            Phase::Downloading => {
                let version = state.latest.as_ref().map_or("", |release| release.version.as_str());
                vec![note(format!("downloading ghostchat {version}…"))]
            }
            Phase::Ready => vec![note("installing the update and restarting…")],
            Phase::Restart => {
                vec![note(state.error.as_deref().unwrap_or("the update is installed. Start ghostchat again."))]
            }
            Phase::Failed => {
                let mut items = vec![note(state.error.as_deref().unwrap_or("the update did not finish."))];
                items.push(
                    button(text("Try again").size(10.5).font(SANS))
                        .on_press(Message::Panel(PanelMsg::Update(UpdateMsg::Install)))
                        .padding([5, 12])
                        .style(theme::accent_button)
                        .into(),
                );
                if let Some(release) = state.latest.as_ref() {
                    items.push(note(format!("latest release: {}", release.version)));
                }
                items
            }
        }
    }

    fn background_section(&self) -> Vec<Element<'_, Message>> {
        let on_off = |on: bool| if on { "on" } else { "off" };
        let mut items = Vec::new();
        if self.background.can_notify() {
            items.push(setting(
                "private messages and mentions",
                "a notification while ghostchat is in the background. it names the sender, never the message.",
                Some(toggle(on_off(!self.social.notifications_off), Message::Panel(PanelMsg::ToggleNotifications))),
            ));
        } else {
            items.push(note("notifications are not available on this system."));
        }
        if self.background.has_tray() {
            items.push(setting(
                "keep running when closed",
                "closing the window leaves ghostchat in the tray, still relaying for the mesh and receiving messages. quit from the tray icon.",
                Some(toggle(on_off(!self.social.quit_on_close), Message::Panel(PanelMsg::ToggleBackground))),
            ));
        }
        if crate::autostart::supported() {
            let about = if self.background.has_tray() {
                "ghostchat starts in the tray when you log in, so phones can reach this PC without opening it."
            } else {
                "ghostchat opens when you log in, so phones can reach this PC."
            };
            items.push(setting(
                "start at login",
                about,
                Some(toggle(on_off(self.background.autostart), Message::Panel(PanelMsg::ToggleAutostart))),
            ));
        }
        items.push(setting(
            "stay awake while relaying",
            "while plugged in, this PC does not fall asleep on its own, so phones nearby keep a relay. closing the lid or choosing sleep still works; on battery it sleeps as usual.",
            Some(toggle(on_off(self.social.stay_awake), Message::Panel(PanelMsg::ToggleStayAwake))),
        ));
        items
    }
}

fn info_tab() -> Element<'static, Message> {
    let mut items: Vec<Element<'static, Message>> = vec![heading("FEATURES")];
    for (title, about) in FEATURES {
        items.push(setting(*title, about, None));
    }
    items.push(heading("SYMBOLS"));
    for (glyph, color, about) in symbols() {
        items.push(
            row![
                container(text(glyph).size(12).font(SYMBOL).color(color)).width(40),
                text(about).size(10.5).line_height(1.5).font(SANS).color(theme::GRAY),
            ]
            .align_y(Alignment::Center)
            .into(),
        );
    }
    items.push(heading("PRIVACY"));
    for (title, about) in PRIVACY {
        items.push(setting(*title, about, None));
    }
    items.push(heading("HOW TO USE"));
    for line in HOW_TO {
        items.push(text(format!("•  {line}")).size(10.5).line_height(1.55).font(SANS).color(theme::GRAY).into());
    }
    items.push(heading("ABOUT"));
    items.push(note(concat!(
        "ghostchat ",
        env!("CARGO_PKG_VERSION"),
        " · MIT license · an independent client, not affiliated with the official bitchat apps."
    )));
    column(items).spacing(8).into()
}

const FEATURES: &[(&str, &str)] = &[
    ("offline communication", "works without internet using Bluetooth low energy"),
    ("end-to-end encryption", "private messages encrypted with the noise protocol"),
    ("extended range", "messages can relay through other peers on the mesh"),
    ("mentions", "use @nickname to notify specific people"),
    ("favorites", "mutual favorites can message over nostr when out of range"),
    ("local channels", "geohash channels to chat with people in nearby regions over decentralized relays"),
    ("voice and files", "voice notes, photos and PDFs over the mesh, encrypted in private chats"),
    (
        "payments",
        "cashu tokens and lightning invoices travel as chat; tap a chip to open a wallet. ghostchat is not a wallet",
    ),
];

const IDENTITY_NOTE: &str = if cfg!(windows) {
    "your identity is a keypair created on this PC, encrypted for your Windows account (DPAPI); panic wipe replaces it"
} else {
    "your identity is a keypair created on this PC, encrypted with the session keyring when it is available; panic wipe replaces it"
};

const PRIVACY: &[(&str, &str)] = &[
    ("no tracking", "no accounts, no phone numbers, no data collection"),
    ("device-local identity", IDENTITY_NOTE),
    ("quiet notifications", "notifications name who wrote, never what they wrote"),
    ("panic mode", "triple-click ghostchat/ to wipe identity, chats, and peers this PC has met (asks to confirm)"),
];

const HOW_TO: &[&str] = &[
    "click your nickname at the top to change it",
    "pick #mesh, a location channel or a person in the sidebar",
    "#location channels… lists your block-to-region cells, bookmarks and teleport",
    "verify someone: they scan your QR in settings; you scan theirs with the camera or a picture",
    "type / for commands; Tab completes. /pay sends a cashu token (public chats need /pay <token> public)",
    "+ or drag a file in to send it; the mic button records a voice note",
    "/clear empties the open chat",
    "/ping nick and /trace nick check how a mesh peer is reached",
    "closing the window keeps ghostchat in the tray (settings > notifications); quit from the tray icon",
];

fn symbols() -> [(&'static str, iced::Color, &'static str); 10] {
    [
        ("★", theme::GOLD, "favorite: enables offline messages via nostr when mutual"),
        ("☾", theme::GRAY, "they favorited you; favorite them back to make it mutual"),
        ("✓", theme::VERIFIED, "identity verified (fingerprint compared or QR scanned)"),
        (
            "·",
            theme::GRAY,
            "private message sent, waiting for the phone (\"queued\": resent when they are back, up to 24 h)",
        ),
        ("✓", theme::GREEN_DIM, "delivered"),
        ("✓✓", theme::GREEN, "read"),
        ("✉", theme::ORANGE, "unread private messages"),
        ("●", theme::GREEN, "talking live (push-to-talk); the voice note follows"),
        ("🎤", theme::ORANGE, "orange mic: someone is talking in #mesh, wait your turn"),
        ("⚑", theme::GOLD, "bookmarked location channel"),
    ]
}

fn heading(label: &str) -> Element<'_, Message> {
    container(text(label).size(8.5).font(SANS_BOLD).color(theme::MUTED))
        .padding(iced::Padding { top: 18.0, bottom: 2.0, ..iced::Padding::ZERO })
        .into()
}

pub(super) fn note(body: impl Into<String>) -> Element<'static, Message> {
    text(body.into()).size(10.5).line_height(1.5).font(SANS).color(theme::GRAY).into()
}

pub(super) fn setting<'a>(
    title: impl Into<String>,
    about: &'a str,
    control: Option<Element<'a, Message>>,
) -> Element<'a, Message> {
    setting_with(title, note(about), control)
}

pub(super) fn setting_with<'a>(
    title: impl Into<String>,
    about: Element<'a, Message>,
    control: Option<Element<'a, Message>>,
) -> Element<'a, Message> {
    let words = column![text(title.into()).size(12).font(SANS_SEMIBOLD).color(theme::TEXT), about].spacing(3);
    match control {
        Some(control) => row![words.width(Length::Fill), control].spacing(16).align_y(Alignment::Center).into(),
        None => words.into(),
    }
}

pub(super) fn toggle(state: &str, press: Message) -> Element<'_, Message> {
    button(text(state).size(10).font(SANS_BOLD)).on_press(press).padding([4, 12]).style(theme::accent_button).into()
}

/// `label  value  [copy]`; `copy` is the raw value when it differs from the shown one.
fn copy_row(label: &str, shown: String, copy: Option<String>) -> Element<'_, Message> {
    let mut line = row![
        container(text(label).size(9).font(SANS).color(theme::MUTED)).width(90),
        text(shown.clone()).size(10.5).font(MONO).color(theme::GREEN_SOFT).width(Length::Fill),
    ]
    .spacing(8)
    .align_y(Alignment::Center);
    if !shown.is_empty() {
        line = line.push(
            button(text("Copy").size(9.5).font(SANS))
                .on_press(Message::Panel(PanelMsg::Copy(copy.unwrap_or(shown))))
                .padding([2, 8])
                .style(theme::accent_button),
        );
    }
    line.into()
}

fn relay_row(url: &str, remove: Option<Message>) -> Element<'_, Message> {
    let tail: Element<'_, Message> = match remove {
        Some(msg) => {
            button(text("Remove").size(9.5).font(SANS)).on_press(msg).padding([2, 8]).style(theme::accent_button).into()
        }
        None => text("Built in").size(9).font(SANS).color(theme::MUTED).into(),
    };
    row![text(url).size(10.5).font(MONO).color(theme::TEXT).width(Length::Fill), tail].align_y(Alignment::Center).into()
}
