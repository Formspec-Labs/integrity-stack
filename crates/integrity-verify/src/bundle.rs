// Rust guideline compliant 2026-02-21
//! Universal deterministic-bundle structural checks.
//!
//! Reads only [`crate::report::BundleEntryView::path`]; the universal
//! phase does not interpret per-file payload bytes. The deterministic
//! bundle invariants checked here:
//!
//! 1. **Sorted paths.** Entries MUST be lexicographically sorted ascending.
//! 2. **Unique paths.** No duplicate paths.
//! 3. **Non-empty paths.** Paths MUST not be empty.

use crate::report::BundleEntryView;

/// One bundle-structural finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BundleStructuralFinding {
    pub kind: &'static str,
    pub entry_index: usize,
    pub message: String,
}

/// Result of [`BundleStructuralCheck::run`].
pub struct BundleStructuralCheck {
    pub findings: Vec<BundleStructuralFinding>,
}

impl BundleStructuralCheck {
    /// Verifies sort / uniqueness / non-empty invariants over the supplied
    /// entries.
    #[must_use]
    pub fn run(entries: &[BundleEntryView<'_>]) -> Self {
        let mut findings = Vec::new();
        let mut prev_path: Option<&str> = None;

        for (index, entry) in entries.iter().enumerate() {
            if entry.path.is_empty() {
                findings.push(BundleStructuralFinding {
                    kind: "path_empty",
                    entry_index: index,
                    message: "bundle entry path is empty".into(),
                });
                continue;
            }
            if let Some(prev) = prev_path {
                match entry.path.cmp(prev) {
                    std::cmp::Ordering::Less => findings.push(BundleStructuralFinding {
                        kind: "path_sort_violation",
                        entry_index: index,
                        message: format!(
                            "path '{}' is lexicographically less than prior path '{prev}'",
                            entry.path
                        ),
                    }),
                    std::cmp::Ordering::Equal => findings.push(BundleStructuralFinding {
                        kind: "path_duplicate",
                        entry_index: index,
                        message: format!("duplicate bundle entry path '{}'", entry.path),
                    }),
                    std::cmp::Ordering::Greater => {}
                }
            }
            prev_path = Some(entry.path);
        }

        Self { findings }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(path: &str) -> BundleEntryView<'_> {
        BundleEntryView { path }
    }

    #[test]
    fn accepts_sorted_unique_paths() {
        let entries = [e("a/x"), e("a/y"), e("b/x")];
        let result = BundleStructuralCheck::run(&entries);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn rejects_sort_violation() {
        let entries = [e("b/x"), e("a/x")];
        let result = BundleStructuralCheck::run(&entries);
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.kind == "path_sort_violation")
        );
    }

    #[test]
    fn rejects_duplicate_path() {
        let entries = [e("a"), e("a")];
        let result = BundleStructuralCheck::run(&entries);
        assert!(result.findings.iter().any(|f| f.kind == "path_duplicate"));
    }

    #[test]
    fn rejects_empty_path() {
        let entries = [e("")];
        let result = BundleStructuralCheck::run(&entries);
        assert!(result.findings.iter().any(|f| f.kind == "path_empty"));
    }
}
