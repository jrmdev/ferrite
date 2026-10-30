//! Side-by-side comparison for the Comparer tool: a line diff with inline
//! word or character changes, bounded in time for large inputs.
use similar::{Algorithm, ChangeTag, DiffOp, TextDiff};
use std::time::Duration;

/// Lines longer than this are marked changed as a whole instead of diffed inline.
const INLINE_LIMIT: usize = 20_000;
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Granularity {
    #[default]
    Words,
    Characters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    Equal,
    Changed,
    Deleted,
    Inserted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub text: String,
    pub changed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    /// One-based line number in its input.
    pub number: usize,
    pub segments: Vec<Segment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub kind: RowKind,
    pub left: Option<Line>,
    pub right: Option<Line>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub equal: usize,
    pub changed: usize,
    pub deleted: usize,
    pub inserted: usize,
}

#[derive(Clone, Debug, Default)]
pub struct Comparison {
    pub rows: Vec<Row>,
    pub stats: Stats,
}
impl Comparison {
    pub fn identical(&self) -> bool {
        self.stats.changed + self.stats.deleted + self.stats.inserted == 0
    }
}

fn trim_newline(line: &str) -> &str {
    line.strip_suffix('\n')
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .unwrap_or(line)
}

fn whole(number: usize, text: &str, changed: bool) -> Line {
    Line {
        number,
        segments: vec![Segment {
            text: trim_newline(text).to_string(),
            changed,
        }],
    }
}

fn push(segments: &mut Vec<Segment>, text: &str, changed: bool) {
    if text.is_empty() {
        return;
    }
    match segments.last_mut() {
        Some(last) if last.changed == changed => last.text.push_str(text),
        _ => segments.push(Segment {
            text: text.into(),
            changed,
        }),
    }
}

/// Inline differences between two versions of a line.
fn inline(left: &str, right: &str, granularity: Granularity) -> (Vec<Segment>, Vec<Segment>) {
    let (left, right) = (trim_newline(left), trim_newline(right));
    if left.len() > INLINE_LIMIT || right.len() > INLINE_LIMIT {
        return (
            vec![Segment {
                text: left.into(),
                changed: true,
            }],
            vec![Segment {
                text: right.into(),
                changed: true,
            }],
        );
    }
    let mut config = TextDiff::configure();
    config.timeout(TIMEOUT);
    let diff = match granularity {
        Granularity::Words => config.diff_words(left, right),
        Granularity::Characters => config.diff_chars(left, right),
    };
    let (mut a, mut b) = (vec![], vec![]);
    for change in diff.iter_all_changes() {
        let text = change.value();
        match change.tag() {
            ChangeTag::Equal => {
                push(&mut a, text, false);
                push(&mut b, text, false);
            }
            ChangeTag::Delete => push(&mut a, text, true),
            ChangeTag::Insert => push(&mut b, text, true),
        }
    }
    (a, b)
}

pub fn compare(left: &str, right: &str, granularity: Granularity) -> Comparison {
    let mut config = TextDiff::configure();
    config.algorithm(Algorithm::Patience).timeout(TIMEOUT);
    let diff = config.diff_lines(left, right);
    let old: Vec<&str> = diff.iter_old_slices().collect();
    let new: Vec<&str> = diff.iter_new_slices().collect();
    let mut comparison = Comparison::default();
    for op in diff.ops() {
        match *op {
            DiffOp::Equal {
                old_index,
                new_index,
                len,
            } => {
                for offset in 0..len {
                    comparison.stats.equal += 1;
                    comparison.rows.push(Row {
                        kind: RowKind::Equal,
                        left: Some(whole(
                            old_index + offset + 1,
                            old[old_index + offset],
                            false,
                        )),
                        right: Some(whole(
                            new_index + offset + 1,
                            new[new_index + offset],
                            false,
                        )),
                    });
                }
            }
            DiffOp::Delete {
                old_index, old_len, ..
            } => {
                for (index, line) in old.iter().enumerate().skip(old_index).take(old_len) {
                    comparison.stats.deleted += 1;
                    comparison.rows.push(Row {
                        kind: RowKind::Deleted,
                        left: Some(whole(index + 1, line, true)),
                        right: None,
                    });
                }
            }
            DiffOp::Insert {
                new_index, new_len, ..
            } => {
                for (index, line) in new.iter().enumerate().skip(new_index).take(new_len) {
                    comparison.stats.inserted += 1;
                    comparison.rows.push(Row {
                        kind: RowKind::Inserted,
                        left: None,
                        right: Some(whole(index + 1, line, true)),
                    });
                }
            }
            DiffOp::Replace {
                old_index,
                old_len,
                new_index,
                new_len,
            } => {
                for offset in 0..old_len.max(new_len) {
                    let row = match (offset < old_len, offset < new_len) {
                        (true, true) => {
                            let (a, b) = inline(
                                old[old_index + offset],
                                new[new_index + offset],
                                granularity,
                            );
                            comparison.stats.changed += 1;
                            Row {
                                kind: RowKind::Changed,
                                left: Some(Line {
                                    number: old_index + offset + 1,
                                    segments: a,
                                }),
                                right: Some(Line {
                                    number: new_index + offset + 1,
                                    segments: b,
                                }),
                            }
                        }
                        (true, false) => {
                            comparison.stats.deleted += 1;
                            Row {
                                kind: RowKind::Deleted,
                                left: Some(whole(
                                    old_index + offset + 1,
                                    old[old_index + offset],
                                    true,
                                )),
                                right: None,
                            }
                        }
                        _ => {
                            comparison.stats.inserted += 1;
                            Row {
                                kind: RowKind::Inserted,
                                left: None,
                                right: Some(whole(
                                    new_index + offset + 1,
                                    new[new_index + offset],
                                    true,
                                )),
                            }
                        }
                    };
                    comparison.rows.push(row);
                }
            }
        }
    }
    comparison
}

/// Split a line's segments into display chunks of at most `width` characters.
pub fn wrap(segments: &[Segment], width: usize) -> Vec<Vec<Segment>> {
    let width = width.max(1);
    let mut chunks = vec![vec![]];
    let mut used = 0;
    for segment in segments {
        let mut rest = segment.text.as_str();
        while !rest.is_empty() {
            if used == width {
                chunks.push(vec![]);
                used = 0;
            }
            let take = rest
                .char_indices()
                .nth(width - used)
                .map_or(rest.len(), |(index, _)| index);
            let (head, tail) = rest.split_at(take);
            used += head.chars().count();
            chunks.last_mut().unwrap().push(Segment {
                text: head.into(),
                changed: segment.changed,
            });
            rest = tail;
        }
    }
    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(segments: &[Segment]) -> String {
        segments.iter().map(|s| s.text.as_str()).collect()
    }

    #[test]
    fn line_and_inline_differences() {
        let a = "GET /a HTTP/1.1\r\nHost: x\r\nCookie: id=1\r\n\r\nbody\n";
        let b = "GET /a HTTP/1.1\r\nHost: x\r\nCookie: id=2\r\nX-New: y\r\n\r\nbody\n";
        let result = compare(a, b, Granularity::Characters);
        assert!(!result.identical());
        assert_eq!(result.stats.changed, 1);
        assert_eq!(result.stats.inserted, 1);
        let changed = result
            .rows
            .iter()
            .find(|r| r.kind == RowKind::Changed)
            .unwrap();
        let left = &changed.left.as_ref().unwrap().segments;
        assert_eq!(text(left), "Cookie: id=1");
        assert!(left.iter().any(|s| s.changed && s.text == "1"));
        assert!(left.iter().any(|s| !s.changed && s.text == "Cookie: id="));
        let inserted = result
            .rows
            .iter()
            .find(|r| r.kind == RowKind::Inserted)
            .unwrap();
        assert_eq!(text(&inserted.right.as_ref().unwrap().segments), "X-New: y");
        assert!(inserted.left.is_none());
        assert!(compare(a, a, Granularity::Words).identical());
    }

    #[test]
    fn word_granularity_marks_whole_tokens() {
        let result = compare(
            "status: pending ok\n",
            "status: approved ok\n",
            Granularity::Words,
        );
        let right = &result.rows[0].right.as_ref().unwrap().segments;
        assert!(right.iter().any(|s| s.changed && s.text == "approved"));
        assert!(right.iter().any(|s| !s.changed && s.text.contains("ok")));
    }

    #[test]
    fn wrapping_preserves_text_and_change_marks() {
        let segments = vec![
            Segment {
                text: "abcdé".into(),
                changed: false,
            },
            Segment {
                text: "XYZ".into(),
                changed: true,
            },
        ];
        let chunks = wrap(&segments, 3);
        assert_eq!(
            chunks.iter().map(|c| text(c)).collect::<Vec<_>>(),
            ["abc", "déX", "YZ"]
        );
        assert!(chunks[1][1].changed && !chunks[1][0].changed);
        assert_eq!(wrap(&[], 10), vec![Vec::<Segment>::new()]);
    }
}
