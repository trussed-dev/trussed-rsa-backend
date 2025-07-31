<!--
Copyright (C) 2022 Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog

## [Unreleased][]

[Unreleased]: https://github.com/trussed-dev/trussed-rsa-backend/compare/v0.3.0...HEAD

- Move `RsaImportFormat` and `RsaPublicParts` to the `trussed-rsa-types` crate.

## [v0.3.0][] (2025-07-31)

[v0.3.0]: https://github.com/trussed-dev/trussed-rsa-backend/compare/v0.2.1...v0.3.0

- Use `trussed-core` and remove default features for `trussed`.
- Add `MECHANISMS` constant with the implemented mechanisms.
- Use `SerializedKey` instead of `Bytes<MAX_KEY_MATERIAL_LENGTH>` when serializing keys.

## [v0.2.1][] (2024-06-21)

[v0.2.1]: https://github.com/trussed-dev/trussed-rsa-backend/compare/v0.2.0...v0.2.1

- Fix missing zeros of RSA implementation ([#12][])

[#12]: https://github.com/trussed-dev/trussed-rsa-backend/pull/12

## [v0.2.0][] (2024-03-22)

[v0.2.0]: https://github.com/trussed-dev/trussed-rsa-backend/compare/v0.1.0...v0.2.0

- Improve documentation ([#4][], [#5][], [#7][])
- Update dependencies:
  - trussed ([#6][])
  - rsa ([#8][])

[#4]: https://github.com/trussed-dev/trussed-rsa-backend/pull/4
[#5]: https://github.com/trussed-dev/trussed-rsa-backend/pull/5
[#6]: https://github.com/trussed-dev/trussed-rsa-backend/pull/6
[#7]: https://github.com/trussed-dev/trussed-rsa-backend/pull/7
[#8]: https://github.com/trussed-dev/trussed-rsa-backend/pull/8

## [v0.1.0][] (2023-04-13)

Initial release

[v0.1.0]: https://github.com/trussed-dev/trussed-rsa-backend/releases/tag/v0.1.0
