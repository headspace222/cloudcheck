# Changelog

All notable changes to CloudCheck are documented here.

---

## [0.2.9] - 2026-08-11

### Added
- CHANGELOG, CONTRIBUTING guide, and full rule reference documentation.
- BCP-002 rule: checks for missing targetScope in subscription-scoped Bicep files.
- Improved inline comment stripping in the AST parser.

### Changed
- README cleaned up. Review link removed.
- Extension description updated in package.json.

---

## [0.2.8] - 2026-08-10

### Changed
- README updated. Cloud Engineering Toolkit link removed.
- Marketplace listing description updated.

---

## [0.2.7] - 2026-08-09

### Changed
- README rewritten. No long dashes. All links corrected.
- Marketplace links for Issues, Repository, Homepage, and License all verified working.

---

## [0.2.6] - 2026-08-08

### Changed
- Icon updated to 256x256 PNG showing bracket and checkmark.
- README updated with correct GitHub and marketplace links.

---

## [0.2.5] - 2026-08-08

### Changed
- Publisher ID corrected to headspace222-dev in package.json.
- All marketplace links fixed.

---

## [0.2.4] - 2026-08-08

### Changed
- README punctuation cleaned up.

---

## [0.2.3] - 2026-08-08

### Changed
- README improved with install instructions and example findings.

---

## [0.2.2] - 2026-08-08

### Fixed
- Publisher ID mismatch resolved.
- Package.json repository, bugs, and homepage URLs corrected.

---

## [0.2.1] - 2026-08-08

### Fixed
- Icon included correctly in packaged vsix.

---

## [0.2.0] - 2026-08-08

### Added
- Full AST parser replacing regex engine.
- Tokeniser for Bicep, Terraform HCL, and ARM JSON.
- Variable reference resolution.
- Nested property path support.
- Exact line number reporting for every finding.
- Specific detail messages per finding.

### Changed
- All 38 rules rewritten to use ParseResult query interface.
- Extension now reports exact line number of each violation.

---

## [0.1.0] - 2026-08-08

### Added
- Initial release.
- 38 compliance rules across 11 categories.
- CIS Azure Benchmark and CAF naming convention mapping.
- Support for Bicep, Terraform HCL, and ARM JSON.
- VS Code Problems panel integration.
- Status bar live issue count.
- Lint on save and lint on type modes.
- Severity filter: all, critical, high, medium.
