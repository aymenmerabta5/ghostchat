//! GhostChat's visual system: graphite ground, mint signal, quiet type.
//!
//! One palette, one radius scale and one button pair. Bright green is a
//! signal (presence, send, selected), never the default text colour; prose
//! sits in the system sans while handles, timestamps and code stay mono.

use iced::widget::{button, container, text_editor, text_input};
use iced::{Background, Border, Color, Shadow, Theme};

/// Primary signal: presence, selection, the send action.
pub const GREEN: Color = Color::from_rgb(0.357, 0.890, 0.541);
/// Borders and quiet signal surfaces.
pub const GREEN_DIM: Color = Color::from_rgb(0.176, 0.420, 0.286);
/// Selected labels and code text: a soft mint, close to white.
pub const GREEN_SOFT: Color = Color::from_rgb(0.851, 0.965, 0.886);
/// Body copy.
pub const TEXT: Color = Color::from_rgb(0.910, 0.933, 0.918);
/// Secondary copy.
pub const GRAY: Color = Color::from_rgb(0.604, 0.655, 0.620);
/// Tertiary labels and placeholders.
pub const MUTED: Color = Color::from_rgb(0.427, 0.490, 0.447);
/// The app canvas.
pub const BG: Color = Color::from_rgb(0.039, 0.051, 0.043);
/// Bars and the sidebar, a step up from the canvas.
pub const BG_SIDE: Color = Color::from_rgb(0.055, 0.071, 0.059);
/// Raised surfaces: rows, the composer, chips.
pub const BG_ROW: Color = Color::from_rgb(0.082, 0.102, 0.086);
/// Selected rows and picked messages.
pub const BG_ROW_SEL: Color = Color::from_rgb(0.102, 0.145, 0.118);
pub const DIVIDER: Color = Color::from_rgb(0.141, 0.173, 0.153);
pub const ALERT: Color = Color::from_rgb(0.949, 0.427, 0.427);
pub const WARN: Color = Color::from_rgb(0.949, 0.722, 0.294);
/// Our own lines keep the warm counterpoint.
pub const ORANGE: Color = Color::from_rgb(1.0, 0.643, 0.357);
pub const GOLD: Color = Color::from_rgb(0.902, 0.773, 0.416);
pub const VERIFIED: Color = Color::from_rgb(0.490, 0.722, 1.0);
/// Location channels keep their blue.
pub const GEO: Color = Color::from_rgb(0.490, 0.722, 1.0);

/// Fenced code cards.
pub const CODE_BG: Color = Color::from_rgb(0.047, 0.066, 0.055);
pub const CODE_KEYWORD: Color = Color::from_rgb(0.941, 0.690, 0.447);
pub const CODE_STRING: Color = Color::from_rgb(0.659, 0.902, 0.690);
pub const CODE_COMMENT: Color = Color::from_rgb(0.373, 0.447, 0.400);
pub const CODE_NUMBER: Color = Color::from_rgb(0.549, 0.784, 1.0);
pub const CODE_FUNCTION: Color = Color::from_rgb(0.502, 0.890, 0.831);

/// Orange (hue ~30 deg) is reserved for us, so peers never get it.
const RESERVED_HUE: f32 = 30.0;
const RESERVED_DELTA: f32 = 18.0;
const HUE_SLOTS: u32 = 36;

/// Stable per-peer nickname color, like iOS `MinimalDistancePalette` but
/// pulled back to a calmer dark-mode saturation.
pub fn peer_color(seed: &str) -> Color {
    let allowed: Vec<f32> = (0..HUE_SLOTS)
        .map(|i| i as f32 * 360.0 / HUE_SLOTS as f32)
        .filter(|h| (h - RESERVED_HUE).abs() > RESERVED_DELTA)
        .collect();
    let hash = seed.bytes().fold(0x811c_9dc5_u32, |h, b| (h ^ b as u32).wrapping_mul(0x0100_0193));
    hsb(allowed[hash as usize % allowed.len()], 0.62, 0.82)
}

fn hsb(hue: f32, saturation: f32, brightness: f32) -> Color {
    let c = brightness * saturation;
    let x = c * (1.0 - ((hue / 60.0) % 2.0 - 1.0).abs());
    let m = brightness - c;
    let (r, g, b) = match (hue / 60.0) as u32 {
        0 => (c, x, 0.0),
        1 => (x, c, 0.0),
        2 => (0.0, c, x),
        3 => (0.0, x, c),
        4 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    Color::from_rgb(r + m, g + m, b + m)
}

pub fn application() -> Theme {
    Theme::custom(
        String::from("ghostchat"),
        iced::theme::Palette { background: BG, text: TEXT, primary: GREEN, success: GREEN, danger: ALERT },
    )
}

pub fn sidebar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_SIDE)),
        text_color: Some(TEXT),
        border: Border { color: DIVIDER, width: 1.0, radius: 0.0.into() },
        shadow: Shadow::default(),
    }
}

pub fn main_pane(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG)),
        text_color: Some(TEXT),
        border: Border::default(),
        shadow: Shadow::default(),
    }
}

/// Full-width bars: top chrome, conversation headers, composer and sheets.
pub fn header_bar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_SIDE)),
        text_color: Some(TEXT),
        border: Border { color: DIVIDER, width: 1.0, radius: 0.0.into() },
        shadow: Shadow::default(),
    }
}

/// A hairline used for day separators and section rules inside the thread.
pub fn rule(_theme: &Theme) -> container::Style {
    container::Style { background: Some(Background::Color(DIVIDER)), ..container::Style::default() }
}

/// Unread-count pill on a conversation row.
pub fn badge(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(GREEN)),
        text_color: Some(BG),
        border: Border { color: GREEN, width: 0.0, radius: 999.0.into() },
        shadow: Shadow::default(),
    }
}

/// Quiet pill for presence counts and metadata in the top bar.
pub fn pill(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_ROW)),
        text_color: Some(GRAY),
        border: Border { color: DIVIDER, width: 1.0, radius: 999.0.into() },
        shadow: Shadow::default(),
    }
}

/// Drop zone shown while a file is dragged over the window.
pub fn badge_outline(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_ROW)),
        text_color: Some(GREEN_SOFT),
        border: Border { color: GREEN_DIM, width: 1.0, radius: 10.0.into() },
        shadow: Shadow::default(),
    }
}

/// Conversation rows: transparent at rest, a quiet surface on hover, and a
/// selected state that reads by surface rather than by a box.
pub fn conv_button(selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_theme: &Theme, status: button::Status| {
        let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
        let bg = if selected {
            BG_ROW_SEL
        } else if hovered {
            BG_ROW
        } else {
            Color::TRANSPARENT
        };
        button::Style {
            background: Some(Background::Color(bg)),
            text_color: if selected { GREEN_SOFT } else { TEXT },
            border: Border { color: Color::TRANSPARENT, width: 0.0, radius: 8.0.into() },
            shadow: Shadow::default(),
        }
    }
}

/// Quiet action: header buttons, chips and secondary verbs.
pub fn accent_button(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg, text, border) = match status {
        button::Status::Hovered | button::Status::Pressed => (BG_ROW, TEXT, DIVIDER),
        button::Status::Disabled => (Color::TRANSPARENT, MUTED, DIVIDER),
        _ => (Color::TRANSPARENT, GRAY, Color::TRANSPARENT),
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: text,
        border: Border { color: border, width: 1.0, radius: 6.0.into() },
        shadow: Shadow::default(),
    }
}

/// One filled action per screen: send, copy, the primary verb.
pub fn primary_button(_theme: &Theme, status: button::Status) -> button::Style {
    let (bg, text) = match status {
        button::Status::Hovered | button::Status::Pressed => (GREEN_SOFT, BG),
        button::Status::Disabled => (BG_ROW, MUTED),
        _ => (GREEN, BG),
    };
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: text,
        border: Border { color: Color::TRANSPARENT, width: 0.0, radius: 8.0.into() },
        shadow: Shadow::default(),
    }
}

pub fn composer(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let focused = matches!(status, text_input::Status::Focused);
    text_input::Style {
        background: Background::Color(BG_ROW),
        border: Border { color: if focused { GREEN_DIM } else { DIVIDER }, width: 1.0, radius: 8.0.into() },
        icon: GRAY,
        placeholder: MUTED,
        value: TEXT,
        selection: GREEN_DIM,
    }
}

/// The multi-line composer: same box as [`composer`], but scrolls its own
/// content once a pasted snippet outgrows the fixed height.
pub fn composer_editor(_theme: &Theme, status: text_editor::Status) -> text_editor::Style {
    let focused = matches!(status, text_editor::Status::Focused);
    text_editor::Style {
        background: Background::Color(BG_ROW),
        border: Border { color: if focused { GREEN_DIM } else { DIVIDER }, width: 1.0, radius: 10.0.into() },
        icon: GRAY,
        placeholder: MUTED,
        value: TEXT,
        selection: GREEN_DIM,
    }
}

/// A checked message box in select mode.
pub fn check_on(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(GREEN)),
        text_color: Some(BG),
        border: Border { color: GREEN, width: 1.0, radius: 4.0.into() },
        shadow: Shadow::default(),
    }
}

/// An empty message box in select mode.
pub fn check_off(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_ROW)),
        text_color: Some(MUTED),
        border: Border { color: MUTED, width: 1.0, radius: 4.0.into() },
        shadow: Shadow::default(),
    }
}

/// The recording strip that replaces the composer.
pub fn recording_panel(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_ROW)),
        text_color: Some(TEXT),
        border: Border { color: ALERT, width: 1.0, radius: 10.0.into() },
        shadow: Shadow::default(),
    }
}

/// A message row picked in select mode.
pub fn selected_message(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_ROW_SEL)),
        text_color: Some(GREEN_SOFT),
        border: Border { color: GREEN_DIM, width: 1.0, radius: 8.0.into() },
        shadow: Shadow::default(),
    }
}

/// One fenced code block: header (language + copy) and unwrapped code.
pub fn code_card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(CODE_BG)),
        text_color: Some(GREEN_SOFT),
        border: Border { color: DIVIDER, width: 1.0, radius: 8.0.into() },
        shadow: Shadow::default(),
    }
}

/// A shared file: extension badge, name, one open action.
pub fn file_card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_ROW)),
        text_color: Some(TEXT),
        border: Border { color: DIVIDER, width: 1.0, radius: 8.0.into() },
        shadow: Shadow::default(),
    }
}

/// The extension badge on a file card, e.g. `IPYNB`.
pub fn attachment_badge(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(BG_ROW_SEL)),
        text_color: Some(GREEN_SOFT),
        border: Border { color: GREEN_DIM, width: 1.0, radius: 5.0.into() },
        shadow: Shadow::default(),
    }
}

/// Payment chip: Cashu / Lightning hand-off, not a chat action.
pub fn chip_button(_theme: &Theme, status: button::Status) -> button::Style {
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    button::Style {
        background: Some(Background::Color(if hovered { BG_ROW_SEL } else { BG_ROW })),
        text_color: TEXT,
        border: Border { color: DIVIDER, width: 1.0, radius: 999.0.into() },
        shadow: Shadow::default(),
    }
}

pub fn icon_button(_theme: &Theme, status: button::Status) -> button::Style {
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    button::Style {
        background: Some(Background::Color(if hovered { BG_ROW } else { Color::TRANSPARENT })),
        text_color: if hovered { TEXT } else { GRAY },
        border: Border::default(),
        shadow: Shadow::default(),
    }
}

/// Inline nickname editor in the header: no box until focused.
pub fn nick_input(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let focused = matches!(status, text_input::Status::Focused);
    text_input::Style {
        background: Background::Color(if focused { BG_ROW } else { Color::TRANSPARENT }),
        border: Border { color: if focused { GREEN_DIM } else { Color::TRANSPARENT }, width: 1.0, radius: 6.0.into() },
        icon: GRAY,
        placeholder: MUTED,
        value: GREEN_SOFT,
        selection: GREEN_DIM,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hue_of(c: Color) -> f32 {
        let max = c.r.max(c.g).max(c.b);
        let min = c.r.min(c.g).min(c.b);
        let d = max - min;
        let h = if max == c.r {
            60.0 * (((c.g - c.b) / d) % 6.0)
        } else if max == c.g {
            60.0 * ((c.b - c.r) / d + 2.0)
        } else {
            60.0 * ((c.r - c.g) / d + 4.0)
        };
        (h + 360.0) % 360.0
    }

    #[test]
    fn peer_colors_are_stable_and_never_orange() {
        assert_eq!(peer_color("aabbccddeeff0011"), peer_color("aabbccddeeff0011"));
        for i in 0..500 {
            let hue = hue_of(peer_color(&format!("peer{i}")));
            assert!((hue - RESERVED_HUE).abs() > RESERVED_DELTA, "hue {hue}");
        }
    }
}
