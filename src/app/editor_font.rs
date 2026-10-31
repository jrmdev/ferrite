use crate::preferences::EditorFont;
use eframe::egui;
use std::sync::{Arc, OnceLock};

fn database() -> &'static fontdb::Database {
    static DATABASE: OnceLock<fontdb::Database> = OnceLock::new();
    DATABASE.get_or_init(|| {
        let mut db = fontdb::Database::new();
        db.load_system_fonts();
        db
    })
}

pub(super) fn faces() -> Vec<String> {
    let mut names: Vec<_> = database()
        .faces()
        .filter(|face| face.monospaced && face.style == fontdb::Style::Normal)
        .filter_map(|face| face.families.first().map(|(name, _)| name.clone()))
        .collect();
    names.sort_unstable_by_key(|name| name.to_lowercase());
    names.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    names
}

pub(super) fn apply(ctx: &egui::Context, font: &EditorFont) {
    let mut definitions = egui::FontDefinitions::default();
    if !font.face.is_empty() {
        let db = database();
        let id = db.query(&fontdb::Query {
            families: &[fontdb::Family::Name(&font.face)],
            ..Default::default()
        });
        if let Some(data) = id.and_then(|id| {
            db.with_face_data(id, |bytes, index| {
                let mut data = egui::FontData::from_owned(bytes.to_vec());
                data.index = index;
                data
            })
        }) {
            let name = format!("editor-font:{}", font.face);
            definitions.font_data.insert(name.clone(), Arc::new(data));
            let mut fallback = definitions.families[&egui::FontFamily::Monospace].clone();
            fallback.insert(0, name.clone());
            definitions
                .families
                .insert(egui::FontFamily::Monospace, fallback);
        }
    }
    ctx.set_fonts(definitions);
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Monospace,
        egui::FontId::new(
            if font.size.is_finite() {
                font.size.clamp(8.0, 36.0)
            } else {
                13.0
            },
            egui::FontFamily::Monospace,
        ),
    );
    ctx.set_style(style);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn font_settings_change_editor_layout_and_missing_faces_fall_back() {
        let ctx = egui::Context::default();
        let font = EditorFont {
            face: "A font that does not exist".into(),
            size: 20.0,
        };
        apply(&ctx, &font);
        let resolved = egui::TextStyle::Monospace.resolve(&ctx.style());
        assert_eq!(resolved.size, 20.0);
        assert_eq!(resolved.family, egui::FontFamily::Monospace);
        if let Some(face) = faces().first() {
            apply(
                &ctx,
                &EditorFont {
                    face: face.clone(),
                    size: 16.0,
                },
            );
            let resolved = egui::TextStyle::Monospace.resolve(&ctx.style());
            assert_eq!(resolved.size, 16.0);
            assert_eq!(resolved.family, egui::FontFamily::Monospace);
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let loaded = ui.fonts_mut(|fonts| {
                        fonts.definitions().families[&egui::FontFamily::Monospace][0].clone()
                    });
                    assert_eq!(loaded, format!("editor-font:{face}"));
                    ui.label(
                        egui::RichText::new("Editor text").text_style(egui::TextStyle::Monospace),
                    );
                });
            });
        }
    }
}
