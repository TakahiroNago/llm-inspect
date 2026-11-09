//! Text normalization applied before pattern matching.
//!
//! Attackers evade naive filters with full-width characters (`ＩＧＮＯＲＥ`),
//! compatibility forms (`ﬁ`) or invisible characters (zero-width spaces,
//! bidirectional controls). [`Normalized`] applies NFKC normalization and drops
//! invisible characters while keeping a byte-offset map back to the original
//! text, so findings and redactions can still be reported on the text the
//! caller actually passed in.

use unicode_normalization::UnicodeNormalization;

/// Returns `true` for characters that are removed during normalization.
///
/// These are format characters that carry no visible content: soft hyphen,
/// zero-width spaces and joiners, bidirectional controls, word joiner and
/// invisible operators, Mongolian vowel separator and the byte-order mark.
pub fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Normalized text with a mapping back to byte offsets in the original.
#[derive(Debug, Clone)]
pub struct Normalized<'a> {
    original: &'a str,
    text: String,
    /// `map[i]` is the byte offset in `original` of the character that produced
    /// byte `i` of `text`. One extra trailing entry holds `original.len()`.
    map: Vec<usize>,
    removed_invisible: usize,
}

impl<'a> Normalized<'a> {
    /// Normalizes `original`.
    pub fn new(original: &'a str) -> Self {
        let mut text = String::with_capacity(original.len());
        let mut map = Vec::with_capacity(original.len() + 1);
        let mut removed_invisible = 0;
        for (offset, c) in original.char_indices() {
            if is_invisible(c) {
                removed_invisible += 1;
                continue;
            }
            for n in std::iter::once(c).nfkc() {
                let before = text.len();
                text.push(n);
                map.extend(std::iter::repeat_n(offset, text.len() - before));
            }
        }
        map.push(original.len());
        Self {
            original,
            text,
            map,
            removed_invisible,
        }
    }

    /// The normalized text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The text that was passed to [`Normalized::new`].
    pub fn original(&self) -> &'a str {
        self.original
    }

    /// Whether normalization changed anything.
    pub fn changed(&self) -> bool {
        self.text != self.original
    }

    /// Number of invisible characters that were removed.
    pub fn removed_invisible(&self) -> usize {
        self.removed_invisible
    }

    /// Maps a byte range of the normalized text back to a byte range of the
    /// original text. The result always covers whole characters of the original.
    ///
    /// # Panics
    ///
    /// Panics if `start > end` or `end > self.text().len()`.
    pub fn to_original(&self, start: usize, end: usize) -> (usize, usize) {
        assert!(
            start <= end && end <= self.text.len(),
            "range out of bounds"
        );
        if start == end {
            let o = self.map[start];
            return (o, o);
        }
        let s = self.map[start];
        let last_src = self.map[end - 1];
        let next = self.map[end];
        let e = if next > last_src {
            next
        } else {
            next_char_boundary(self.original, last_src)
        };
        (s, e)
    }
}

fn next_char_boundary(s: &str, i: usize) -> usize {
    let mut j = i + 1;
    while j < s.len() && !s.is_char_boundary(j) {
        j += 1;
    }
    j.min(s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_ascii_is_unchanged() {
        let n = Normalized::new("hello world");
        assert!(!n.changed());
        assert_eq!(n.to_original(6, 11), (6, 11));
    }

    #[test]
    fn full_width_maps_back_to_original_bytes() {
        let src = "say ＩＧＮＯＲＥ now"; // each full-width letter is 3 bytes
        let n = Normalized::new(src);
        assert_eq!(n.text(), "say IGNORE now");
        let (s, e) = n.to_original(4, 10);
        assert_eq!(&src[s..e], "ＩＧＮＯＲＥ");
    }

    #[test]
    fn zero_width_characters_are_removed_and_counted() {
        let src = "ig\u{200B}no\u{200D}re";
        let n = Normalized::new(src);
        assert_eq!(n.text(), "ignore");
        assert_eq!(n.removed_invisible(), 2);
        let (s, e) = n.to_original(0, 6);
        assert_eq!((s, e), (0, src.len()));
    }

    #[test]
    fn partial_match_inside_expanded_char_covers_whole_source_char() {
        let src = "ﬁle"; // U+FB01 expands to "fi"
        let n = Normalized::new(src);
        assert_eq!(n.text(), "file");
        let (s, e) = n.to_original(0, 1); // just "f"
        assert_eq!(&src[s..e], "ﬁ");
    }

    #[test]
    fn empty_input() {
        let n = Normalized::new("");
        assert_eq!(n.text(), "");
        assert_eq!(n.to_original(0, 0), (0, 0));
    }
}
