# DKIM Milter changelog

All notable user-facing changes are listed in this changelog.

This project follows Rust-flavoured [semantic versioning], with changes to the
minimum supported Rust version being considered breaking changes.

[semantic versioning]: https://doc.rust-lang.org/cargo/reference/semver.html

## 0.2.0-alpha.1 (2024-06-13)

With this release, development has moved from GitLab to the [Codeberg] platform.

The minimum supported Rust version is now 1.74.0.

[Codeberg]: https://codeberg.org

### Changed

* The minimum supported Rust version has been raised to 1.74.0.

* Parameters formerly pointing to table-like files now recognise a *data source*
  prefix. This concerns parameters `signing_senders`, `signing_keys`,
  `connection_overrides`, and `recipient_overrides`.

  Previously, these parameters only allowed table-like files that were read and
  validated eagerly; this behaviour is now represented by data source
  `<`/`slurp:`: For example, `signing_keys = </path/to/file` is the new
  equivalent of former `signing_keys = /path/to/file`. Though, for backwards
  compatibility, the bare path continues to have the same meaning as the
  prefixed path.

  With this change, reading and validation of table files has been overhauled,
  and some error messages have been adjusted.

* Configuration errors detected at runtime now result in a transient SMTP error
  reply being sent to the client. Previously, configuration was always validated
  eagerly and such errors were not possible.

* In parameter `reject_failures`, value `author-mismatch` now causes signatures
  from authors where the *From* domain is a subdomain of the signing domain to
  be treated as acceptable. Previously only exact matches where tolerated; exact
  matching is still available through new value `author-mismatch-strict`.

### Added

* New data source `file:` has been added to support for configuration data being
  continually read from the filesystem.

* New data source `sqlite:` has been added for SQLite database support. This
  data source is enabled with new Cargo feature `sqlite`.

### Fixed

* Header names in `oversign_headers` that did not occur in the input message are
  now properly included in *h=* nevertheless.

## 0.1.0 (2023-12-27)

Initial release.
