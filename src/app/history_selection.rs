use std::collections::{BTreeSet, HashSet};

#[derive(Default)]
pub(super) struct HistorySelection {
    pub ids: BTreeSet<u64>,
    pub focused: Option<u64>,
    anchor: Option<u64>,
}

impl HistorySelection {
    pub fn select_all(&mut self, visible: &[u64]) {
        self.ids = visible.iter().copied().collect();
        if !self.focused.is_some_and(|id| self.ids.contains(&id)) {
            self.focused = visible.first().copied();
        }
        self.anchor = self.focused;
    }

    pub fn retain_visible(&mut self, visible: &[u64]) {
        let visible_ids: HashSet<_> = visible.iter().copied().collect();
        self.ids.retain(|id| visible_ids.contains(id));
        if self.anchor.is_some_and(|id| !visible_ids.contains(&id)) {
            self.anchor = None;
        }
        if self.focused.is_some_and(|id| !self.ids.contains(&id)) {
            self.focused = visible.iter().find(|id| self.ids.contains(id)).copied();
        }
    }

    pub fn click(&mut self, id: u64, visible: &[u64], toggle: bool, range: bool, context: bool) {
        if context && self.ids.contains(&id) {
            self.focused = Some(id);
            return;
        }
        if range && !context {
            let anchor = self
                .anchor
                .and_then(|anchor| visible.iter().position(|id| *id == anchor));
            let end = visible.iter().position(|item| *item == id);
            if let (Some(start), Some(end)) = (anchor, end) {
                if !toggle {
                    self.ids.clear();
                }
                self.ids.extend(&visible[start.min(end)..=start.max(end)]);
                self.focused = Some(id);
                return;
            }
        }
        if toggle && !context {
            if !self.ids.remove(&id) {
                self.ids.insert(id);
            }
        } else {
            self.ids.clear();
            self.ids.insert(id);
        }
        self.anchor = Some(id);
        self.focused = if self.ids.contains(&id) {
            Some(id)
        } else {
            visible.iter().find(|id| self.ids.contains(id)).copied()
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toggle_range_and_context_selection_follow_exchange_ids() {
        let visible = [8, 3, 5, 1];
        let mut selection = HistorySelection::default();
        selection.click(8, &visible, false, false, false);
        selection.click(5, &visible, true, false, false);
        assert_eq!(selection.ids, BTreeSet::from([8, 5]));
        selection.click(8, &visible, false, false, true);
        assert_eq!(selection.ids.len(), 2);
        selection.click(1, &visible, false, true, false);
        assert_eq!(selection.ids, BTreeSet::from([5, 1]));
        let sorted = [1, 3, 5, 8];
        selection.click(8, &sorted, false, true, false);
        assert_eq!(selection.ids, BTreeSet::from([5, 8]));
        selection.click(3, &sorted, false, false, true);
        assert_eq!(selection.ids, BTreeSet::from([3]));
        selection.click(3, &sorted, true, false, false);
        assert!(selection.ids.is_empty());
        assert_eq!(selection.focused, None);
    }

    #[test]
    fn filtering_discards_hidden_rows_and_keeps_visible_selection() {
        let mut selection = HistorySelection::default();
        selection.click(1, &[1, 2, 3], false, false, false);
        selection.click(3, &[1, 2, 3], false, true, false);
        selection.retain_visible(&[2]);
        assert_eq!(selection.ids, BTreeSet::from([2]));
        assert_eq!(selection.focused, Some(2));
        selection.retain_visible(&[]);
        assert_eq!(selection.focused, None);
    }
}
