# Change Log
All notable changes to this project will be documented in this file.

## [Unreleased]

### Fixes
- Fixed unit test failing when using the default unifont files
- Font descriptor data was not utilised properly

### Changed
- New parameter added to MultiCell - which allows you to limit the number of lines the MultiCell should use at most. If the parameter is passed the Multicell will return a string with the remaining text, which did not fit.

## [v2.0.5]

### Fixes
- "U" style did not actually underline the text.

[Unreleased]: https://github.com/DocnetUK/tfpdf/compare/v2.0.5...HEAD
[v2.0.5]: https://github.com/DocnetUK/tfpdf/compare/v2.0.4...v2.0.5
