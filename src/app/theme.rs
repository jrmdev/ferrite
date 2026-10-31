use crate::model::ColorScheme;
use eframe::egui::{self, Color32, Stroke};

pub(super) fn timestamp_text(
    ui: &egui::Ui,
    text: &str,
    font: egui::FontId,
    color: Color32,
) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let split = text.rfind('.').unwrap_or(text.len());
    job.append(
        &text[..split],
        0.0,
        egui::TextFormat::simple(font.clone(), color),
    );
    if split < text.len() {
        let lighter = color.lerp_to_gamma(
            Color32::WHITE,
            if ui.visuals().dark_mode { 0.35 } else { 0.25 },
        );
        job.append(&text[split..], 0.0, egui::TextFormat::simple(font, lighter));
    }
    job
}

pub(super) fn message_background(visuals: &egui::Visuals) -> Color32 {
    if visuals.dark_mode {
        let panel = visuals.panel_fill;
        Color32::from_rgb(
            panel.r().saturating_add(10),
            panel.g().saturating_add(10),
            panel.b().saturating_add(10),
        )
    } else {
        visuals.extreme_bg_color
    }
}

pub(super) fn status_color(visuals: &egui::Visuals, status: u16) -> Color32 {
    let rgb = match (visuals.dark_mode, status / 100) {
        (false, 1) => [132, 75, 0],
        (false, 2) => [24, 100, 49],
        (false, 3) => [30, 56, 120],
        (false, 4) => [128, 32, 64],
        (false, 5) => [112, 44, 148],
        (true, 1) => [238, 183, 87],
        (true, 2) => [94, 184, 120],
        (true, 3) => [125, 155, 230],
        (true, 4) => [224, 132, 156],
        (true, 5) => [191, 145, 230],
        _ => return visuals.text_color(),
    };
    Color32::from_rgb(rgb[0], rgb[1], rgb[2])
}

pub fn apply(ctx: &egui::Context, scheme: ColorScheme) {
    let mut visuals = match scheme {
        ColorScheme::Light
        | ColorScheme::PaleBlue
        | ColorScheme::PaleGreen
        | ColorScheme::PaleRed
        | ColorScheme::PaleGrey
        | ColorScheme::PalePurple
        | ColorScheme::PaleYellow
        | ColorScheme::Cappuccino
        | ColorScheme::DesertMirage => egui::Visuals::light(),
        _ => egui::Visuals::dark(),
    };
    let palette = match scheme {
        ColorScheme::PaleBlue => Some((
            [222, 238, 248],
            [237, 247, 253],
            [202, 225, 240],
            [24, 45, 62],
            [30, 101, 148],
        )),
        ColorScheme::PaleGreen => Some((
            [225, 241, 229],
            [241, 249, 243],
            [205, 230, 211],
            [28, 58, 38],
            [42, 126, 72],
        )),
        ColorScheme::PaleRed => Some((
            [248, 229, 229],
            [253, 243, 243],
            [239, 207, 207],
            [73, 31, 31],
            [176, 61, 61],
        )),
        ColorScheme::PaleGrey => Some((
            [232, 235, 238],
            [246, 247, 248],
            [214, 219, 224],
            [42, 48, 54],
            [82, 103, 122],
        )),
        ColorScheme::PalePurple => Some((
            [239, 230, 247],
            [249, 243, 253],
            [222, 207, 236],
            [57, 35, 73],
            [126, 72, 166],
        )),
        ColorScheme::PaleYellow => Some((
            [249, 243, 211],
            [254, 250, 232],
            [238, 226, 169],
            [67, 57, 21],
            [161, 124, 25],
        )),
        ColorScheme::Dracula => Some((
            [40, 42, 54],
            [33, 34, 44],
            [68, 71, 90],
            [248, 248, 242],
            [189, 147, 249],
        )),
        ColorScheme::Nord => Some((
            [46, 52, 64],
            [36, 41, 51],
            [67, 76, 94],
            [236, 239, 244],
            [136, 192, 208],
        )),
        ColorScheme::SolarizedDark => Some((
            [0, 43, 54],
            [0, 35, 43],
            [7, 54, 66],
            [147, 161, 161],
            [42, 161, 152],
        )),
        // Adapted from Figma's named color combinations, with surface and text
        // shades chosen for a readable, low-glare application interface.
        ColorScheme::DesertDusk => Some((
            [61, 34, 45],
            [45, 24, 35],
            [82, 45, 56],
            [255, 237, 229],
            [230, 128, 87],
        )),
        ColorScheme::RetroSunset => Some((
            [49, 39, 28],
            [35, 29, 23],
            [69, 54, 39],
            [255, 245, 221],
            [255, 206, 27],
        )),
        ColorScheme::NeonNoir => Some((
            [25, 25, 25],
            [18, 18, 18],
            [45, 45, 45],
            [241, 247, 237],
            [44, 255, 5],
        )),
        ColorScheme::Cappuccino => Some((
            [235, 222, 204],
            [250, 244, 235],
            [215, 198, 177],
            [67, 39, 1],
            [113, 70, 25],
        )),
        ColorScheme::DesertMirage => Some((
            [238, 229, 205],
            [252, 248, 235],
            [220, 211, 182],
            [39, 39, 87],
            [155, 52, 33],
        )),
        ColorScheme::EmeraldOdyssey => Some((
            [11, 61, 48],
            [7, 44, 35],
            [0, 76, 59],
            [245, 255, 251],
            [114, 230, 202],
        )),
        ColorScheme::AutumnOrchard => Some((
            [65, 24, 45],
            [48, 16, 32],
            [87, 37, 60],
            [255, 239, 225],
            [245, 190, 59],
        )),
        ColorScheme::CobaltSky => Some((
            [21, 38, 78],
            [13, 24, 57],
            [33, 56, 103],
            [233, 244, 255],
            [130, 200, 229],
        )),
        _ => None,
    };
    if let Some((background, panel, widget, text, accent)) = palette {
        let color = |v: [u8; 3]| Color32::from_rgb(v[0], v[1], v[2]);
        visuals.panel_fill = color(background);
        visuals.window_fill = color(panel);
        visuals.extreme_bg_color = color(panel);
        visuals.faint_bg_color = color(widget);
        visuals.override_text_color = Some(color(text));
        for state in [
            &mut visuals.widgets.noninteractive,
            &mut visuals.widgets.inactive,
            &mut visuals.widgets.hovered,
            &mut visuals.widgets.active,
            &mut visuals.widgets.open,
        ] {
            state.bg_fill = color(widget);
            state.weak_bg_fill = color(widget);
            state.fg_stroke.color = color(text);
        }
        let mix = |a: [u8; 3], b: [u8; 3], amount: u16| {
            let blend =
                |i: usize| ((a[i] as u16 * (100 - amount) + b[i] as u16 * amount) / 100) as u8;
            Color32::from_rgb(blend(0), blend(1), blend(2))
        };
        visuals.widgets.hovered.bg_fill = mix(widget, accent, 20);
        visuals.widgets.hovered.weak_bg_fill = visuals.widgets.hovered.bg_fill;
        visuals.widgets.active.bg_fill = mix(widget, accent, 35);
        visuals.widgets.active.weak_bg_fill = visuals.widgets.active.bg_fill;
        visuals.widgets.open.bg_fill = mix(widget, accent, 15);
        visuals.widgets.open.weak_bg_fill = visuals.widgets.open.bg_fill;
        visuals.selection.bg_fill = mix(panel, accent, 35);
        visuals.selection.stroke = Stroke::new(1.0_f32, color(accent));
        visuals.hyperlink_color = color(accent);
    }
    // set_visuals only changes the active egui style; it does not select a theme.
    // Pin the user's scheme before the first native OS-theme event can arrive.
    ctx.set_theme(if visuals.dark_mode {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    });
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing.y = 9.0;
        style.spacing.button_padding.y = 5.0;
        style.spacing.interact_size.y = 26.0;
    });
    ctx.set_visuals(visuals);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_color_scheme_can_be_applied() {
        let ctx = egui::Context::default();
        for scheme in ColorScheme::ALL {
            apply(&ctx, scheme);
            assert_eq!(
                ctx.style().visuals.dark_mode,
                !scheme.label().starts_with("Pale")
                    && !matches!(
                        scheme,
                        ColorScheme::Light | ColorScheme::Cappuccino | ColorScheme::DesertMirage
                    )
            );
        }
    }

    #[test]
    fn figma_palettes_keep_text_readable_and_round_trip() {
        fn luminance(color: Color32) -> f32 {
            let channel = |value: u8| {
                let value = value as f32 / 255.0;
                if value <= 0.04045 {
                    value / 12.92
                } else {
                    ((value + 0.055) / 1.055).powf(2.4)
                }
            };
            0.2126 * channel(color.r()) + 0.7152 * channel(color.g()) + 0.0722 * channel(color.b())
        }
        fn contrast(a: Color32, b: Color32) -> f32 {
            let (a, b) = (luminance(a), luminance(b));
            (a.max(b) + 0.05) / (a.min(b) + 0.05)
        }
        for scheme in [
            ColorScheme::DesertDusk,
            ColorScheme::RetroSunset,
            ColorScheme::NeonNoir,
            ColorScheme::Cappuccino,
            ColorScheme::DesertMirage,
            ColorScheme::EmeraldOdyssey,
            ColorScheme::AutumnOrchard,
            ColorScheme::CobaltSky,
        ] {
            let serialized = serde_json::to_string(&scheme).unwrap();
            assert_eq!(
                serde_json::from_str::<ColorScheme>(&serialized).unwrap(),
                scheme
            );
            let ctx = egui::Context::default();
            apply(&ctx, scheme);
            let visuals = &ctx.style().visuals;
            let text = visuals.text_color();
            for background in [
                visuals.panel_fill,
                visuals.window_fill,
                visuals.widgets.inactive.bg_fill,
                visuals.widgets.hovered.bg_fill,
                visuals.widgets.active.bg_fill,
                visuals.selection.bg_fill,
            ] {
                assert!(
                    contrast(text, background) >= 4.5,
                    "{scheme:?} text contrast is {}",
                    contrast(text, background)
                );
            }
            assert!(
                contrast(visuals.hyperlink_color, visuals.panel_fill) >= 4.5,
                "{scheme:?} link contrast"
            );
        }
    }

    #[test]
    fn native_theme_events_do_not_change_control_spacing_or_the_selected_palette() {
        fn controls(ctx: &egui::Context, system_theme: egui::Theme) -> (f32, f32, f32) {
            let mut sizes = (0.0, 0.0, 0.0);
            let mut text = String::new();
            let _ = ctx.run(
                egui::RawInput {
                    system_theme: Some(system_theme),
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(600.0, 300.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let first = ui.button("Save").rect;
                        let second = ui.text_edit_singleline(&mut text).rect;
                        sizes = (
                            first.height(),
                            second.height(),
                            second.top() - first.bottom(),
                        );
                    });
                },
            );
            sizes
        }
        for scheme in [
            ColorScheme::Light,
            ColorScheme::PalePurple,
            ColorScheme::Dark,
            ColorScheme::Nord,
        ] {
            let ctx = egui::Context::default();
            apply(&ctx, scheme);
            let expected = ctx.style().visuals.clone();
            let baseline = controls(&ctx, egui::Theme::Dark);
            assert!(baseline.0 >= 26.0);
            assert_eq!(
                baseline,
                controls(&ctx, egui::Theme::Light),
                "Native light theme changed control geometry for {scheme:?}"
            );
            assert_eq!(ctx.style().visuals.panel_fill, expected.panel_fill);
            assert_eq!(ctx.style().visuals.dark_mode, expected.dark_mode);
            assert_eq!(baseline, controls(&ctx, egui::Theme::Dark));
        }
    }
}
