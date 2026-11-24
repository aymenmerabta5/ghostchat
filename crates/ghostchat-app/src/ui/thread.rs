//! The message thread, composer and fingerprint panel.

use super::code;
use super::markup;
use super::view::{ITALIC, MONO, MONO_SEMIBOLD, SANS, SANS_BOLD, SANS_SEMIBOLD, SYMBOL};
use super::{App, Message};
use crate::inbox::{Conversation, Entry, Media};
use crate::mesh_worker::Delivery;
use crate::theme;
use chrono::NaiveDate;
use ghostchat_protocol::{format_fingerprint, MediaKind};
use iced::widget::text::Span;
use iced::widget::{
    button, column, container, image, rich_text, row, scrollable, span, text, text_editor, tooltip, Space,
};
use iced::{Alignment, ContentFit, Element, Font, Length};
use std::time::Duration;

/// iOS shows photos as roughly phone-width thumbnails; this fits the pane.
const PREVIEW_WIDTH: f32 = 280.0;

impl App {
    /// The open group's roster, plus the nearby peers not in it, so invites
    /// happen with one click instead of remembering nicknames.
    pub(super) fn group_member_panel(&self, id: &str) -> Element<'_, Message> {
        let Some(group) = self.group_summary(id) else {
            return container(text("group details are loading…").size(12).color(theme::GRAY))
                .padding([6, 16])
                .width(Length::Fill)
                .style(theme::header_bar)
                .into();
        };
        let mut rows: Vec<Element<'_, Message>> = vec![section_label("MEMBERS")];
        for member in &group.members {
            let dot = if member.online { "●" } else { "○" };
            let dot_color = if member.online { theme::GREEN } else { theme::MUTED };
            let mut line = row![
                text(dot).size(7).color(dot_color),
                text(member.nickname.clone()).size(11.5).font(SANS_SEMIBOLD).color(if member.is_me {
                    theme::ORANGE
                } else {
                    theme::TEXT
                }),
            ]
            .spacing(7)
            .align_y(Alignment::Center);
            if member.is_me {
                line = line.push(text("you").size(9).font(SANS).color(theme::MUTED));
            }
            if member.is_creator {
                line = line.push(text("CREATOR").size(8).font(SANS_BOLD).color(theme::GOLD));
            }
            line = line.push(
                text(member.fingerprint.chars().take(12).collect::<String>()).size(9).font(MONO).color(theme::MUTED),
            );
            line = line.push(Space::with_width(Length::Fill));
            if group.is_creator && !member.is_me && !member.is_creator {
                line = line.push(
                    button(text("remove").size(11))
                        .on_press(Message::GroupRemove(member.nickname.clone()))
                        .padding([2, 6])
                        .style(theme::accent_button),
                );
            }
            rows.push(line.into());
        }
        let in_group = |peer_id: &str| group.members.iter().any(|m| m.peer_id.as_deref() == Some(peer_id));
        let invitees: Vec<_> = self.roster.online_peers().filter(|p| !in_group(&p.id)).collect();
        if group.is_creator && !invitees.is_empty() {
            rows.push(section_label("NEARBY, NOT IN THIS GROUP"));
            for peer in invitees {
                rows.push(
                    row![
                        text(self.display_name(&peer.id)).size(11.5).font(SANS).color(theme::peer_color(&peer.id)),
                        Space::with_width(Length::Fill),
                        button(text("invite").size(10.5))
                            .on_press(Message::GroupInvite(peer.id.clone()))
                            .padding([3, 8])
                            .style(theme::accent_button),
                    ]
                    .spacing(6)
                    .align_y(Alignment::Center)
                    .into(),
                );
            }
        }
        if !group.is_creator {
            rows.push(
                text("only the creator can invite or remove people").size(10).font(SANS).color(theme::MUTED).into(),
            );
        }
        container(column(rows).spacing(5)).padding([10, 20]).width(Length::Fill).style(theme::header_bar).into()
    }

    pub(super) fn fingerprint_panel(&self, id: &str) -> Element<'_, Message> {
        let theirs = self.fingerprint_of(id);
        let verified = theirs.as_deref().is_some_and(|fp| self.social.is_verified(fp));
        let their_text =
            theirs.as_deref().map(format_fingerprint).unwrap_or_else(|| "unknown until they announce".into());
        let verify_label = if verified { "remove verification" } else { "mark verified" };
        let mut verify = button(text(verify_label).size(10.5)).padding([4, 9]).style(theme::accent_button);
        if theirs.is_some() {
            verify = verify.on_press(Message::ToggleVerified(id.to_string()));
        }
        let name = self.display_name(id);
        container(
            row![
                column![
                    text(format!("{name}'s fingerprint")).size(9.5).font(SANS).color(theme::MUTED),
                    text(their_text).size(11).font(MONO).color(theme::peer_color(id)),
                ]
                .spacing(4),
                column![
                    text("your fingerprint").size(9.5).font(SANS).color(theme::MUTED),
                    text(format_fingerprint(&self.fingerprint)).size(11).font(MONO).color(theme::ORANGE),
                ]
                .spacing(4),
                Space::with_width(Length::Fill),
                column![text("compare in person, then").size(9.5).font(SANS).color(theme::MUTED), verify,]
                    .spacing(5)
                    .align_x(Alignment::End),
            ]
            .spacing(32)
            .padding([12, 20]),
        )
        .width(Length::Fill)
        .style(theme::sidebar)
        .into()
    }

    pub(super) fn thread(&self) -> Element<'_, Message> {
        let visible = self.inbox.visible(&self.selected);
        if visible.is_empty() {
            let hint = match self.selected {
                Conversation::Mesh => "No messages in #mesh yet. Say hi to everyone nearby.",
                Conversation::Dm(_) => "Just type. GhostChat secures the chat and sends once both sides are ready.",
                Conversation::Geo(_) => {
                    "Nobody has posted in this area yet. Messages travel to Nostr relays near it."
                }
                Conversation::GeoDm { .. } => {
                    "A private channel between your key for this area and theirs. Gift-wrapped over Nostr, never linked to your mesh identity."
                }
                Conversation::Group(_) => {
                    "No group messages yet. /group invite <nick> adds someone nearby; everyone in the group reads what you send."
                }
            };
            return container(
                text(hint)
                    .size(13)
                    .line_height(1.55)
                    .font(SANS)
                    .color(theme::GRAY)
                    .width(Length::Fixed(430.0))
                    .align_x(Alignment::Center),
            )
            .width(Length::Fill)
            .center(Length::Fill)
            .into();
        }
        let stamps: Vec<u64> = visible.iter().map(|e| e.line.timestamp_ms).collect();
        let today = chrono::Local::now().date_naive();
        let mut rows: Vec<Element<'static, Message>> = Vec::with_capacity(visible.len());
        // Consecutive lines from one person inside five minutes share a
        // header, the way mature chat clients keep a busy thread quiet.
        let mut previous: Option<(&str, u64)> = None;
        for (entry, day) in visible.into_iter().zip(day_breaks(&stamps, today)) {
            if let Some(day) = day {
                rows.push(day_separator(day, today));
                previous = None;
            }
            let line = &entry.line;
            let grouped = !entry.system
                && !line.is_self
                && previous.is_some_and(|(sender, at)| {
                    sender == sender_key(line)
                        && line.timestamp_ms >= at
                        && line.timestamp_ms.saturating_sub(at) < 5 * 60 * 1000
                });
            let row = self.line_row(entry, grouped);
            rows.push(self.selectable_row(entry, row));
            previous = if entry.system || line.is_self { None } else { Some((sender_key(line), line.timestamp_ms)) };
        }
        let list = container(column(rows).padding([20, 28]).width(Length::Fill)).max_width(960).width(Length::Fill);
        let content = container(list).width(Length::Fill).center_x(Length::Fill);
        scrollable(content).anchor_bottom().width(Length::Fill).height(Length::Fill).into()
    }

    /// In select mode every real message gets a checkbox; the whole row is
    /// tinted once picked. System notices never take part.
    fn selectable_row(&self, entry: &Entry, row: Element<'static, Message>) -> Element<'static, Message> {
        if !self.select_mode || entry.system || entry.line.id.is_empty() {
            return row;
        }
        let checked = self.selected_lines.contains(&entry.line.id);
        let mark = text(if checked { "✓" } else { "" }).size(9).font(SANS_BOLD).color(theme::BG).center();
        let boxed =
            container(mark).width(16).height(16).style(if checked { theme::check_on } else { theme::check_off });
        let pick =
            button(boxed).on_press(Message::SelectLine(entry.line.id.clone())).padding(2).style(theme::icon_button);
        let body = container(row).padding([5, 8]).width(Length::Fill);
        let body = if checked { body.style(theme::selected_message) } else { body };
        row![pick, body].spacing(8).align_y(Alignment::Start).into()
    }

    /// One message: handle and time on a quiet meta line, body underneath.
    /// Grouped lines drop the meta so a run of messages reads as one block.
    fn line_row(&self, entry: &Entry, grouped: bool) -> Element<'static, Message> {
        let line = &entry.line;
        if entry.system {
            let spans: Vec<Span<'static, Message>> = vec![
                span(line.content.clone()).color(theme::MUTED).font(ITALIC),
                span(format!("  {}", format_time(line.timestamp_ms))).color(theme::MUTED).size(9).font(MONO),
            ];
            return container(rich(spans).size(11.5).line_height(1.45)).padding([5, 0]).into();
        }
        let body = self.message_body(line, entry);
        if grouped {
            return container(body).padding([2, 0]).into();
        }
        let (nick, nick_color) = if line.is_self {
            (self.self_label(), theme::ORANGE)
        } else {
            (self.sender_name(line), theme::peer_color(sender_key(line)))
        };
        let mut meta = row![
            text(format!("@{nick}")).size(11.5).font(MONO_SEMIBOLD).color(nick_color),
            text(format_time(line.timestamp_ms)).size(9.5).font(MONO).color(theme::MUTED),
        ]
        .spacing(9)
        .align_y(Alignment::Center);
        if let Some(note) = self.delivery_note(line) {
            meta = meta.push(note);
        }
        container(column![meta, body].spacing(5)).padding([9, 0]).into()
    }

    fn message_body(&self, line: &ghostchat_core::ChatLine, entry: &Entry) -> Element<'static, Message> {
        // Voice notes sit inline, like the iOS voice bubble; the
        // "[voice] 48 KB" caption would only repeat the player.
        if let Some(media) = &entry.media {
            if media.kind == MediaKind::Audio {
                let playing = self.voice.playing() == Some(media.path.as_path());
                return row![voice_button(media, playing), reveal_link(media)]
                    .spacing(10)
                    .align_y(Alignment::Center)
                    .into();
            }
        }
        let me = self.mention_name();
        let payment_only = crate::pay::is_payment_only(&line.content);
        let chips = payment_chips(&line.content);
        let mut body: Vec<Element<'static, Message>> = Vec::new();
        if !payment_only && !line.content.is_empty() {
            for block in code::blocks(&line.content) {
                match block {
                    code::Block::Text(text) => {
                        let spans = markup::body_spans(text, theme::TEXT, &me);
                        if !spans.is_empty() {
                            body.push(container(rich(spans).size(14).line_height(1.5)).max_width(720).into());
                        }
                    }
                    code::Block::Code { lang, code } => body.push(code_block(lang, code)),
                }
            }
        }
        if let Some(chips) = chips {
            body.push(chips);
        }
        if let Some(media) = &entry.media {
            body.push(attachment(media));
        }
        match body.len() {
            0 => Space::with_height(0).into(),
            1 => body.pop().expect("one body row"),
            _ => column(body).spacing(6).into(),
        }
    }

    /// Upload progress or the delivery mark, only for our own lines.
    fn delivery_note(&self, line: &ghostchat_core::ChatLine) -> Option<Element<'static, Message>> {
        if !line.is_self {
            return None;
        }
        let sending = self.inbox.sending(&line.id);
        let (label, color) = if let Some(percent) = sending.filter(|p| *p < 100) {
            (format!("sending {percent}%"), theme::MUTED)
        } else if !line.is_private && sending == Some(100) {
            ("sent".into(), theme::MUTED)
        } else if line.is_private {
            match self.inbox.delivery(&line.id) {
                Some(Delivery::Read) => ("read".into(), theme::GREEN),
                Some(Delivery::Delivered) => ("delivered".into(), theme::GRAY),
                Some(Delivery::Failed) => ("not delivered".into(), theme::ALERT),
                Some(Delivery::Queued) => ("queued".into(), theme::GRAY),
                Some(Delivery::Couriered { forward_secret: true }) => ("courier · forward secret".into(), theme::GRAY),
                Some(Delivery::Couriered { forward_secret: false }) => ("courier".into(), theme::GRAY),
                None => return None,
            }
        } else {
            return None;
        };
        let dot = text("·").size(9).font(SANS).color(theme::MUTED);
        Some(row![dot, text(label).size(9).font(SANS).color(color)].spacing(5).align_y(Alignment::Center).into())
    }

    pub(super) fn composer(&self) -> Element<'_, Message> {
        let placeholder = match &self.selected {
            Conversation::Mesh => "Message #mesh".to_string(),
            Conversation::Dm(id) => format!("Message {}", self.display_name(id)),
            Conversation::Geo(cell) => format!("Message #{}", cell),
            Conversation::GeoDm { cell, pubkey } => format!("Message {}", self.geo_dm_name(cell, pubkey)),
            Conversation::Group(id) => {
                let name = self.group_summary(id).map(|g| g.name.clone()).unwrap_or_else(|| "the group".into());
                format!("Message #{name}")
            }
        };
        if let Some(elapsed) = self.recorder.elapsed() {
            let bar = container(recording_bar(elapsed))
                .padding(iced::Padding { top: 0.0, right: 28.0, bottom: 0.0, left: 28.0 })
                .max_width(960)
                .width(Length::Fill);
            return container(container(bar).width(Length::Fill).center_x(Length::Fill))
                .padding([14, 0])
                .width(Length::Fill)
                .style(theme::header_bar)
                .into();
        }
        // Group media is chunked into normal group messages, so attach and
        // record work there too; only location channels have no media path.
        let can_attach = !matches!(self.selected, Conversation::Geo(_) | Conversation::GeoDm { .. });
        let attach = button(text("+  Attach").size(10.5).font(SANS))
            .on_press_maybe(can_attach.then_some(Message::PickFile))
            .padding([5, 10])
            .style(theme::accent_button);
        // Floor courtesy (iOS): someone is live in #mesh. Recording still
        // works; a mesh has no arbiter, so this only discourages talk-over.
        let busy = matches!(self.selected, Conversation::Mesh).then(|| self.mesh_talkers()).flatten();
        let rec_label = row![
            text("●").size(7).color(if busy.is_some() { theme::ORANGE } else { theme::ALERT }),
            text("Record").size(10.5).font(SANS),
        ]
        .spacing(6)
        .align_y(Alignment::Center);
        let record = button(rec_label)
            .on_press_maybe(can_attach.then_some(Message::RecordStart))
            .padding([5, 10])
            .style(theme::accent_button);
        let record: Element<'_, Message> = match busy {
            Some(who) => tooltip(record, text(format!("{who} is talking")).size(11), tooltip::Position::Top)
                .style(theme::header_bar)
                .into(),
            None => record.into(),
        };
        let send = button(text("Send").size(11).font(SANS_BOLD))
            .on_press(Message::Submit)
            .padding([7, 18])
            .style(theme::primary_button);
        // Location channels have no media path; an inert Attach/Record pair
        // would only suggest otherwise.
        let tools: Element<'_, Message> = if can_attach {
            row![attach, record].spacing(8).align_y(Alignment::Center).into()
        } else {
            Space::with_width(0).into()
        };
        let actions = row![
            tools,
            Space::with_width(Length::Fill),
            text("Enter sends · Shift+Enter for a new line").size(10).font(SANS).color(theme::MUTED),
            send,
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        let editor = container(
            text_editor(&self.composer)
                .placeholder(placeholder)
                .on_action(Message::DraftChanged)
                .key_binding(super::composer::editor_key_binding(!self.slash_suggestions().is_empty()))
                .padding(10)
                .size(14)
                .height(Length::Fixed(78.0))
                .wrapping(text::Wrapping::WordOrGlyph)
                .style(theme::composer_editor),
        )
        .id(super::composer_container_id())
        .width(Length::Fill);
        let column = column![self.suggestion_list(), editor, actions].spacing(8).padding(iced::Padding {
            top: 12.0,
            right: 28.0,
            bottom: 12.0,
            left: 28.0,
        });
        // Keep the writing column on the same edges as the thread above it.
        let panel = container(column).max_width(960).width(Length::Fill);
        container(container(panel).width(Length::Fill).center_x(Length::Fill))
            .width(Length::Fill)
            .style(theme::header_bar)
            .into()
    }

    /// Replaces the composer while messages are being picked for copying.
    pub(super) fn selection_bar(&self) -> Element<'_, Message> {
        let count = self.selected_count();
        let noun = if count == 1 { "message" } else { "messages" };
        let copy = button(text("Copy").size(11).font(SANS_BOLD))
            .on_press_maybe((count > 0).then_some(Message::CopySelected))
            .padding([7, 18])
            .style(theme::primary_button);
        let bar = row![
            text(format!("{count} {noun} selected")).size(12).font(SANS_SEMIBOLD).color(theme::TEXT),
            text("Shift-click for a range · Ctrl+C copies · Esc cancels").size(9.5).font(SANS).color(theme::MUTED),
            Space::with_width(Length::Fill),
            button(text("Select all").size(10.5).font(SANS))
                .on_press(Message::SelectAll)
                .padding([6, 12])
                .style(theme::accent_button),
            copy,
            button(text("Done").size(10.5).font(SANS))
                .on_press(Message::ToggleSelectMode)
                .padding([6, 12])
                .style(theme::accent_button),
        ]
        .spacing(10)
        .align_y(Alignment::Center)
        .padding(iced::Padding { top: 14.0, right: 28.0, bottom: 14.0, left: 28.0 });
        let bar = container(bar).max_width(960).width(Length::Fill);
        container(container(bar).width(Length::Fill).center_x(Length::Fill))
            .width(Length::Fill)
            .style(theme::header_bar)
            .into()
    }

    /// Commands matching the draft, above the composer (Telegram-style).
    fn suggestion_list(&self) -> Element<'_, Message> {
        let rows: Vec<Element<'_, Message>> = self
            .slash_suggestions()
            .into_iter()
            .enumerate()
            .map(|(i, cmd)| {
                let line = row![
                    text(cmd.name).size(11).font(MONO_SEMIBOLD).color(theme::GREEN_SOFT),
                    text(cmd.args).size(9.5).font(MONO).color(theme::MUTED),
                    Space::with_width(Length::Fill),
                    text(cmd.about).size(10).font(SANS).color(theme::GRAY),
                ]
                .spacing(10)
                .align_y(Alignment::Center);
                button(line)
                    .on_press(Message::SlashChosen(i))
                    .padding([4, 10])
                    .width(Length::Fill)
                    .style(theme::conv_button(i == self.slash_pick))
                    .into()
            })
            .collect();
        column(rows).spacing(1).into()
    }

    /// Shown instead of the thread while a file is dragged over the window.
    pub(super) fn drop_target(&self) -> Element<'_, Message> {
        let label = match &self.selected {
            Conversation::Mesh => "Drop to send to everyone in #mesh".to_string(),
            Conversation::Dm(id) => format!("Drop to send privately to {}", self.display_name(id)),
            Conversation::Geo(_) | Conversation::GeoDm { .. } => "Location chats are text only".to_string(),
            Conversation::Group(id) => {
                let name = self.group_summary(id).map(|g| g.name.clone()).unwrap_or_else(|| "this group".into());
                format!("Drop to send to everyone in #{name}")
            }
        };
        container(
            column![
                text("Release to send").size(9).font(SANS_BOLD).color(theme::MUTED),
                text(label).size(13).font(SANS).color(theme::TEXT)
            ]
            .spacing(6),
        )
        .center(Length::Fill)
        .style(theme::badge_outline)
        .into()
    }
}

/// Replaces the input while a voice note records: timer, cancel, send.
fn recording_bar(elapsed: Duration) -> Element<'static, Message> {
    let max = crate::recorder::MAX_RECORDING;
    let shown = elapsed.min(max).as_millis() as u64;
    container(
        row![
            text("●").size(7).font(SYMBOL).color(theme::ALERT),
            text(format!(
                "Recording {} / {}",
                crate::voice::format_duration(shown),
                crate::voice::format_duration(max.as_millis() as u64)
            ))
            .size(11.5)
            .font(SANS)
            .color(theme::ALERT),
            Space::with_width(Length::Fill),
            button(text("Cancel").size(10.5))
                .on_press(Message::RecordFinish(false))
                .padding([6, 12])
                .style(theme::accent_button),
            button(text("Send").size(11).font(SANS_BOLD))
                .on_press(Message::RecordFinish(true))
                .padding([7, 18])
                .style(theme::primary_button),
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    )
    .padding(10)
    .width(Length::Fill)
    .style(theme::recording_panel)
    .into()
}

/// Cashu / Lightning chips under a chat line. Tap hands the string to a
/// registered wallet (`cashu:` / `lightning:`) or the Cashu web redeem page.
fn payment_chips(content: &str) -> Option<Element<'static, Message>> {
    let chips = crate::pay::chips(content);
    if chips.is_empty() {
        return None;
    }
    let buttons: Vec<Element<'static, Message>> = chips
        .into_iter()
        .map(|chip| {
            let url = chip.open_url();
            let copy = chip.copy_text();
            let label = match &chip {
                crate::pay::Chip::Cashu { label, memo, .. } => match memo {
                    Some(memo) => format!("{label} · {memo}"),
                    None => label.clone(),
                },
                crate::pay::Chip::Lightning { label, .. } => label.clone(),
            };
            row![
                button(text(label).size(11).font(SANS))
                    .on_press(Message::OpenPayment(url))
                    .padding([6, 12])
                    .style(theme::chip_button),
                button(text("Copy").size(9.5).font(SANS))
                    .on_press(Message::Panel(super::panel::PanelMsg::Copy(copy)))
                    .padding([2, 5])
                    .style(theme::icon_button),
            ]
            .spacing(6)
            .align_y(Alignment::Center)
            .into()
        })
        .collect();
    Some(row(buttons).spacing(8).into())
}

/// A fenced code card: language label, copy button, and unwrapped code in a
/// horizontal scroller so indentation and long lines survive intact.
fn code_block(lang: Option<&str>, code: &str) -> Element<'static, Message> {
    let label = lang.unwrap_or("code").to_ascii_uppercase().chars().take(24).collect::<String>();
    let copy = code.to_string();
    let highlighted = rich_text(code::spans(code, lang))
        .font(Font::MONOSPACE)
        .size(13)
        .line_height(1.55)
        .wrapping(text::Wrapping::None);
    let scroller = scrollable(highlighted)
        .direction(scrollable::Direction::Horizontal(scrollable::Scrollbar::new()))
        .width(Length::Fill);
    container(column![
        row![
            text(label).size(8.5).font(SANS_BOLD).color(theme::MUTED),
            Space::with_width(Length::Fill),
            button(text("Copy").size(9.5).font(SANS))
                .on_press(Message::CopyText(copy))
                .padding([2, 6])
                .style(theme::icon_button),
        ]
        .spacing(6)
        .align_y(Alignment::Center)
        .padding([7, 10]),
        container(Space::with_height(1)).width(Length::Fill).style(theme::rule),
        container(scroller).padding([9, 12]),
    ])
    .width(Length::Fill)
    .style(theme::code_card)
    .into()
}

/// Inline preview for images (the picture and "Open image" open the full
/// file), or a file card with its extension, name and open/reveal actions.
fn attachment(media: &Media) -> Element<'static, Message> {
    match media.kind {
        MediaKind::Image => container(
            column![
                button(
                    image(image::Handle::from_path(&media.path))
                        .width(Length::Fixed(PREVIEW_WIDTH))
                        .content_fit(ContentFit::Contain)
                )
                .on_press(Message::OpenPath(media.path.clone()))
                .padding(0)
                .style(theme::icon_button),
                row![
                    button(text("Open image").size(9.5).font(SANS))
                        .on_press(Message::OpenPath(media.path.clone()))
                        .padding(0)
                        .style(theme::icon_button),
                    reveal_link(media),
                ]
                .spacing(12),
            ]
            .spacing(4),
        )
        .into(),
        _ => {
            let name =
                media.path.file_name().and_then(|n| n.to_str()).map(str::to_owned).unwrap_or_else(|| "file".into());
            let ext = media
                .path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.to_ascii_uppercase())
                .filter(|e| e.len() <= 8)
                .unwrap_or_else(|| "FILE".into());
            let badge = container(text(ext).size(8).font(SANS_BOLD).color(theme::GREEN_SOFT))
                .padding([5, 7])
                .style(theme::attachment_badge);
            let details = column![
                text(name).size(11.5).font(SANS_SEMIBOLD).color(theme::TEXT).wrapping(text::Wrapping::None),
                text("Open · show in folder").size(9).font(SANS).color(theme::MUTED),
            ]
            .spacing(2);
            container(
                row![
                    badge,
                    details,
                    Space::with_width(Length::Fill),
                    button(text("Open").size(9.5).font(SANS))
                        .on_press(Message::OpenPath(media.path.clone()))
                        .padding([4, 10])
                        .style(theme::accent_button),
                    reveal_link(media),
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            )
            .padding([8, 10])
            .width(Length::Fill)
            .style(theme::file_card)
            .into()
        }
    }
}

/// Play/stop with the note's length. Never starts on its own: there is no
/// auto-play until a user-facing on/off setting exists.
fn voice_button(media: &Media, playing: bool) -> Element<'static, Message> {
    button(text(voice_label(playing, media.duration_ms)).size(11).font(SYMBOL).color(theme::GREEN_SOFT))
        .on_press(Message::PlayVoice(media.path.clone()))
        .padding([5, 10])
        .style(theme::accent_button)
        .into()
}

fn reveal_link(media: &Media) -> Element<'static, Message> {
    button(text("Show in folder").size(9.5).font(SANS).color(theme::GRAY))
        .on_press(Message::RevealPath(media.path.clone()))
        .padding([2, 4])
        .style(theme::icon_button)
        .into()
}

fn voice_label(playing: bool, duration_ms: Option<u64>) -> String {
    let icon = if playing { "■" } else { "▶" };
    match duration_ms {
        Some(ms) => format!("{icon}  {}", crate::voice::format_duration(ms)),
        None => format!("{icon}  voice note"),
    }
}

fn rich(spans: Vec<Span<'static, Message>>) -> text::Rich<'static, Message, iced::Theme, iced::Renderer> {
    rich_text(spans).wrapping(text::Wrapping::WordOrGlyph)
}

fn local_day(ms: u64) -> Option<NaiveDate> {
    (ms > 0)
        .then(|| chrono::DateTime::from_timestamp_millis(ms as i64))
        .flatten()
        .map(|dt| dt.with_timezone(&chrono::Local).date_naive())
}

/// Where a day label goes: before the first line unless it is from today,
/// and wherever the day changes (threads span days with saved history).
fn day_breaks(stamps: &[u64], today: NaiveDate) -> Vec<Option<NaiveDate>> {
    let mut previous = Some(today);
    stamps
        .iter()
        .map(|ms| {
            let day = local_day(*ms);
            let shown = day.filter(|d| Some(*d) != previous);
            if day.is_some() {
                previous = day;
            }
            shown
        })
        .collect()
}

fn day_separator(day: NaiveDate, today: NaiveDate) -> Element<'static, Message> {
    let label = match (today - day).num_days() {
        0 => "TODAY".to_string(),
        1 => "YESTERDAY".to_string(),
        _ => day.format("%b %-d, %Y").to_string().to_uppercase(),
    };
    container(
        row![
            container(Space::with_height(1)).width(Length::Fill).style(theme::rule),
            text(label).size(8.5).font(SANS_BOLD).color(theme::MUTED),
            container(Space::with_height(1)).width(Length::Fill).style(theme::rule),
        ]
        .spacing(14)
        .align_y(Alignment::Center),
    )
    .padding([14, 0])
    .width(Length::Fill)
    .into()
}

/// A quiet section heading inside the group panel.
fn section_label(label: &'static str) -> Element<'static, Message> {
    container(text(label).size(8.5).font(SANS_BOLD).color(theme::MUTED)).padding([8, 0]).into()
}

/// Who wrote a line, for grouping consecutive messages. Peer ids stay stable
/// even when two people pick the same nickname.
fn sender_key(line: &ghostchat_core::ChatLine) -> &str {
    line.peer_id.as_ref().map(|p| p.hex.as_str()).unwrap_or(line.from.as_str())
}

fn format_time(ms: u64) -> String {
    if ms == 0 {
        return "--:--".into();
    }
    chrono::DateTime::from_timestamp_millis(ms as i64)
        .map(|dt| dt.with_timezone(&chrono::Local).format("%H:%M").to_string())
        .unwrap_or_else(|| "--:--".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration as Days, Local, TimeZone};

    fn noon(day: NaiveDate) -> u64 {
        let dt = Local.from_local_datetime(&day.and_hms_opt(12, 0, 0).unwrap()).unwrap();
        dt.timestamp_millis() as u64
    }

    #[test]
    fn day_labels_mark_only_changes() {
        let today = Local::now().date_naive();
        let yesterday = today - Days::days(1);
        let stamps = [noon(yesterday), noon(yesterday), noon(today), noon(today), 0];
        assert_eq!(day_breaks(&stamps, today), [Some(yesterday), None, Some(today), None, None]);
        assert_eq!(day_breaks(&[noon(today)], today), [None], "a fresh session shows no label");
    }
}
