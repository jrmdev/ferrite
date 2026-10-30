//! Decoder: chained byte transformations with intermediate results.
use super::{Workbench, subsection_heading};
use crate::{decoder::Transform, http};
use eframe::egui::{self, RichText};

type StepResults = Vec<Result<Vec<u8>, String>>;

pub(super) struct State {
    input: String,
    input_hex: bool,
    steps: Vec<Transform>,
    hex_output: Vec<bool>,
    cache: Option<(u64, StepResults)>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            input: String::new(),
            input_hex: false,
            steps: vec![Transform::Base64Decode],
            hex_output: vec![false],
            cache: None,
        }
    }
}

/// Text when the bytes display faithfully, otherwise a hex dump.
fn display(bytes: &[u8], hex: bool) -> (String, bool) {
    if !hex && http::is_display_text(bytes) {
        (String::from_utf8_lossy(bytes).into_owned(), false)
    } else {
        (http::hex_dump(bytes), true)
    }
}

impl State {
    pub(super) fn set_input(&mut self, bytes: &[u8]) {
        let (text, hex) = http::editor_text(bytes);
        self.input = text;
        self.input_hex = hex;
        self.cache = None;
    }
    fn input_bytes(&self) -> Result<Vec<u8>, String> {
        if self.input_hex {
            http::parse_hex(&self.input).map_err(|e| e.to_string())
        } else {
            Ok(self.input.as_bytes().to_vec())
        }
    }
    fn results(&mut self) -> Result<&[Result<Vec<u8>, String>], String> {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (&self.input, self.input_hex, &self.steps).hash(&mut hasher);
        let key = hasher.finish();
        if self.cache.as_ref().is_none_or(|(k, _)| *k != key) {
            let input = self.input_bytes()?;
            self.cache = Some((key, crate::decoder::run_chain(&input, &self.steps)));
        }
        Ok(&self.cache.as_ref().unwrap().1)
    }
}

impl Workbench {
    pub(super) fn decoder(&mut self, ui: &mut egui::Ui) {
        ui.heading("Decoder");
        ui.add(
            egui::Label::new(
                RichText::new("Apply transformations in sequence. Each step works on the previous step's bytes; binary results are shown as hex.")
                    .weak(),
            )
            .wrap(),
        );
        let state = &mut self.decoder;
        ui.horizontal(|ui| {
            subsection_heading(ui, "Input");
            ui.radio_value(&mut state.input_hex, false, "Text");
            ui.radio_value(&mut state.input_hex, true, "Hex");
            if ui.button("Clear").clicked() {
                state.input.clear();
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("decoder-input-scroll")
            .max_height(140.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut state.input)
                        .id(egui::Id::new("decoder-input"))
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(5)
                        .desired_width(f32::INFINITY)
                        .hint_text("Paste text, a token, or hex bytes"),
                );
            });
        ui.add_space(6.0);
        let results = state.results();
        let results: Vec<Result<Vec<u8>, String>> = match results {
            Ok(results) => results.to_vec(),
            Err(error) => {
                ui.colored_label(ui.visuals().error_fg_color, format!("Input: {error}"));
                vec![]
            }
        };
        state.hex_output.resize(state.steps.len(), false);
        let mut remove = None;
        let mut swap = None;
        let mut use_as_input = None;
        let count = state.steps.len();
        for index in 0..count {
            ui.push_id(("decoder-step", index), |ui| {
                ui.separator();
                ui.horizontal(|ui| {
                    ui.label(RichText::new(format!("Step {}", index + 1)).strong());
                    egui::ComboBox::from_id_salt("transform")
                        .selected_text(state.steps[index].label())
                        .width(240.0)
                        .show_ui(ui, |ui| {
                            for transform in Transform::ALL {
                                ui.selectable_value(
                                    &mut state.steps[index],
                                    transform,
                                    transform.label(),
                                );
                            }
                        });
                    if ui.add_enabled(index > 0, egui::Button::new("Up")).clicked() {
                        swap = Some((index - 1, index));
                    }
                    if ui
                        .add_enabled(index + 1 < count, egui::Button::new("Down"))
                        .clicked()
                    {
                        swap = Some((index, index + 1));
                    }
                    if ui.button("Remove").clicked() {
                        remove = Some(index);
                    }
                    ui.checkbox(&mut state.hex_output[index], "Hex");
                });
                match results.get(index) {
                    Some(Ok(bytes)) => {
                        let (text, hex) = display(bytes, state.hex_output[index]);
                        ui.horizontal(|ui| {
                            ui.weak(format!(
                                "{} bytes{}",
                                bytes.len(),
                                if hex && !state.hex_output[index] {
                                    " · binary, shown as hex"
                                } else {
                                    ""
                                }
                            ));
                            if ui.small_button("Copy").clicked() {
                                ui.ctx().copy_text(if hex {
                                    http::hex_dump(bytes)
                                } else {
                                    text.clone()
                                });
                            }
                            if ui.small_button("Use as input").clicked() {
                                use_as_input = Some(bytes.clone());
                            }
                        });
                        egui::ScrollArea::vertical()
                            .id_salt("output")
                            .max_height(180.0)
                            .show(ui, |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut text.as_str())
                                        .font(egui::TextStyle::Monospace)
                                        .desired_rows(2)
                                        .desired_width(f32::INFINITY),
                                );
                            });
                    }
                    Some(Err(error)) => {
                        ui.colored_label(ui.visuals().error_fg_color, error);
                    }
                    None => {
                        ui.weak("Not run: an earlier step failed.");
                    }
                }
            });
        }
        ui.separator();
        ui.horizontal_wrapped(|ui| {
            if ui.button("Add step").clicked() {
                let next = state
                    .steps
                    .last()
                    .copied()
                    .unwrap_or(Transform::Base64Decode);
                state.steps.push(next);
            }
            ui.weak("Quick add:");
            for transform in [
                Transform::UrlDecode,
                Transform::Base64Decode,
                Transform::HtmlDecode,
                Transform::HexDecode,
                Transform::JwtDecode,
                Transform::Sha256,
            ] {
                if ui.small_button(transform.label()).clicked() {
                    state.steps.push(transform);
                }
            }
        });
        if let Some(index) = remove {
            state.steps.remove(index);
            state.hex_output.remove(index);
        }
        if let Some((a, b)) = swap {
            state.steps.swap(a, b);
            state.hex_output.swap(a, b);
        }
        if let Some(bytes) = use_as_input {
            state.set_input(&bytes);
            state.steps.clear();
            state.steps.push(Transform::Base64Decode);
            state.hex_output = vec![false];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_results_are_cached_and_follow_input() {
        let mut state = State::default();
        state.set_input(b"aGVsbG8=");
        assert_eq!(state.results().unwrap()[0].as_deref().unwrap(), b"hello");
        state.steps.push(Transform::HexEncode);
        assert_eq!(
            state.results().unwrap()[1].as_deref().unwrap(),
            b"68656c6c6f"
        );
        state.set_input(&[0, 1, 2]);
        assert!(state.input_hex);
        assert_eq!(state.input_bytes().unwrap(), [0, 1, 2]);
        assert_eq!(display(&[0, 1], false), ("00 01".into(), true));
        assert_eq!(display(b"ok", false), ("ok".into(), false));
    }
}
