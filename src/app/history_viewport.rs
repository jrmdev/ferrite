use super::history_table::HistorySort;

pub(super) const ROW_PITCH: f32 = 22.0;

#[derive(Default)]
pub(super) struct HistoryViewport {
    top: Option<u64>,
    index: usize,
    offset: f32,
    sort: Option<HistorySort>,
    top_striped: bool,
}

impl HistoryViewport {
    fn anchored_index(&self, rows: &[u64], sort: HistorySort) -> Option<usize> {
        if self.offset <= 1.0 || self.sort != Some(sort) {
            return None;
        }
        let id = self.top?;
        if rows.get(self.index) == Some(&id) {
            Some(self.index)
        } else {
            rows.iter().position(|row| *row == id)
        }
    }

    pub fn restore(&self, rows: &[u64], sort: HistorySort) -> (f32, bool) {
        self.anchored_index(rows, sort)
            .map_or((0.0, false), |index| {
                (
                    index as f32 * ROW_PITCH + self.offset.rem_euclid(ROW_PITCH),
                    self.top_striped != index.is_multiple_of(2),
                )
            })
    }

    pub fn record(&mut self, rows: &[u64], offset: f32, sort: HistorySort, invert_stripes: bool) {
        self.offset = offset.max(0.0);
        self.index = (self.offset / ROW_PITCH).floor() as usize;
        self.top = rows.get(self.index).copied();
        self.top_striped = self.index.is_multiple_of(2) != invert_stripes;
        self.sort = Some(sort);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incoming_rows_preserve_the_viewed_exchange_and_partial_row_offset() {
        let mut viewport = HistoryViewport::default();
        let sort = HistorySort::default();
        let rows: Vec<_> = (1..=100).rev().collect();
        viewport.record(&rows, ROW_PITCH * 30.0 + 7.0, sort, false);
        let added: Vec<_> = (1..=105).rev().collect();
        let (next, invert) = viewport.restore(&added, sort);
        assert_eq!(next, ROW_PITCH * 35.0 + 7.0);
        assert_eq!(rows[30], added[(next / ROW_PITCH).floor() as usize]);
        assert!(invert);
        assert!(35_usize.is_multiple_of(2) != invert);
        viewport.record(&added, next, sort, invert);
        let more: Vec<_> = (1..=106).rev().collect();
        assert!(!viewport.restore(&more, sort).1);
        viewport.record(&added, 0.0, sort, invert);
        assert_eq!(viewport.restore(&more, sort), (0.0, false));
    }
}
