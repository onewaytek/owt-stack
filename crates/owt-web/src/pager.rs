//! One page of a numbered list.

/// Page `number` (from 1) of `pages`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pager {
    /// This page, from 1.
    pub number: usize,
    /// How many pages there are; at least 1.
    pub pages: usize,
}

impl Pager {
    /// Page `requested` of `items` at `per_page`. Garbage and out-of-range numbers
    /// land on the first or last page rather than failing: a stale link still shows
    /// something.
    #[must_use]
    pub fn clamped(requested: Option<&str>, items: usize, per_page: usize) -> Pager {
        let pages = items.div_ceil(per_page.max(1)).max(1);
        let number = requested
            .and_then(|p| p.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, pages);
        Pager { number, pages }
    }

    /// Where this page starts in the whole list.
    #[must_use]
    pub fn offset(&self, per_page: usize) -> usize {
        (self.number - 1) * per_page
    }

    /// More than one page.
    #[must_use]
    pub fn is_paginated(&self) -> bool {
        self.pages > 1
    }

    /// A page before this one.
    #[must_use]
    pub fn has_previous(&self) -> bool {
        self.number > 1
    }

    /// A page after this one.
    #[must_use]
    pub fn has_next(&self) -> bool {
        self.number < self.pages
    }

    /// The previous page's number (0 on the first).
    #[must_use]
    pub fn previous(&self) -> usize {
        self.number.saturating_sub(1)
    }

    /// The next page's number.
    #[must_use]
    pub fn next(&self) -> usize {
        self.number + 1
    }

    /// Every page number.
    #[must_use]
    pub fn numbers(&self) -> std::ops::RangeInclusive<usize> {
        1..=self.pages
    }

    /// Within one page of this one: the numbered links a compact pager draws.
    #[must_use]
    pub fn is_near(&self, n: usize) -> bool {
        n + 2 > self.number && n < self.number + 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamps_out_of_range_pages() {
        assert_eq!(
            Pager::clamped(Some("99"), 17, 8),
            Pager {
                number: 3,
                pages: 3
            }
        );
        assert_eq!(
            Pager::clamped(Some("x"), 17, 8),
            Pager {
                number: 1,
                pages: 3
            }
        );
        assert_eq!(
            Pager::clamped(None, 0, 8),
            Pager {
                number: 1,
                pages: 1
            }
        );
        assert_eq!(Pager::clamped(Some("2"), 17, 8).offset(8), 8);
        assert!(
            Pager {
                number: 3,
                pages: 9
            }
            .is_near(4)
        );
        assert!(
            !Pager {
                number: 3,
                pages: 9
            }
            .is_near(5)
        );
    }

    #[test]
    fn navigation_follows_the_numbers() {
        let one = Pager {
            number: 1,
            pages: 1,
        };
        assert!(!one.is_paginated());
        assert!(!one.has_previous() && !one.has_next());
        assert_eq!((one.previous(), one.next()), (0, 2));
        let two = Pager {
            number: 1,
            pages: 2,
        };
        assert!(two.is_paginated());
        assert!(!two.has_previous() && two.has_next());
        let middle = Pager {
            number: 5,
            pages: 9,
        };
        assert!(middle.has_previous() && middle.has_next());
        assert_eq!((middle.previous(), middle.next()), (4, 6));
        assert_eq!(
            middle.numbers().collect::<Vec<_>>(),
            (1..=9).collect::<Vec<_>>()
        );
        // Near: this page and its neighbours, nothing further.
        let near: Vec<usize> = (0..=9).filter(|n| middle.is_near(*n)).collect();
        assert_eq!(near, vec![4, 5, 6]);
        let first: Vec<usize> = (0..=9).filter(|n| two.is_near(*n)).collect();
        assert_eq!(first, vec![0, 1, 2]);
    }
}
