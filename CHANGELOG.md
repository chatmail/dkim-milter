# DKIM Milter changelog

All notable user-facing changes are listed in this changelog.

This project follows Rust-flavoured [semantic versioning], with changes to the
minimum supported Rust version being considered breaking changes.

[semantic versioning]: https://doc.rust-lang.org/cargo/reference/semver.html

## 0.2.0 (unreleased)

### Added

* New data source (see below) `file:` has been added to support for data being
  continually read from the filesystem.

* New data source `sqlite:` has been added for SQLite database support.

  This data source is enabled with new Cargo feature `sqlite`.

### Changed

* Parameters formerly pointing to table-like files now recognise a *data source*
  prefix. This concerns parameters `signing_senders`, `signing_keys`,
  `connection_overrides`, `recipient_overrides`.

  The former behaviour can be kept by prefixing the values with `<`: For
  example, `signing_keys = /path/to/file` becomes `signing_keys =
  </path/to/file`. (For backwards compatibility, bare paths for now keep the
  same meaning as the `<`-prefixed paths.)

  With this change, reading and validation of table files has been overhauled,
  and some error messages have been adjusted.

## 0.1.0 (2023-12-27)

Initial release.
