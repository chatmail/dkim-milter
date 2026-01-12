> [!NOTE]
> This is a fork of https://codeberg.org/glts/dkim-milter
> 
> Chatmail-specific patches:
> - unix sockets use 760 mode

# DKIM Milter

DKIM Milter is a milter application that signs and verifies email messages using
the *DomainKeys Identified Mail* (DKIM) protocol. It is meant to be integrated
with a milter-capable MTA (mail server) such as [Postfix]. DKIM is specified in
[RFC 6376].

DKIM Milter is based on the [viadkim] library. Therefore, it inherits the
approach to DKIM used in that library. Notably, viadkim fully supports
internationalised email, including Unicode signing domains in the `d=` tag (RFC
8616). More practically, it inherits the performance characteristics of viadkim
when processing many, or large, messages, and integrates them with the
asynchronous-paradigm milter implementation.

DKIM Milter tries to work efficiently. Public key queries are done in parallel.
When multiple signatures use the same parameters for calculating the body hash,
the hash is calculated only once, and the result is shared among the signatures.
Also, when the body hash does not need to be calculated, such as when the
signature was already determined to be failing, body processing is skipped
entirely. A further example is the handling of large messages: DKIM Milter
processes message bodies in chunks of fixed size, meaning that it does not come
under pressure even when processing hundreds of messages of one or two megabytes
each simultaneously; the *total* memory used for these messages’ bodies at any
point in time will never exceed a few megabytes or so (ie, a ceiling relative to
the number of messages, not their size).

DKIM Milter can be used as a simple alternative to the OpenDKIM milter. Credit
goes to that project, of which I have been a long-time user and which has
inspired some choices made here.

[Postfix]: https://www.postfix.org
[RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
[viadkim]: https://crates.io/crates/viadkim

## Installation

DKIM Milter is a [Rust] project. It can be built and/or installed using Cargo as
usual. For example, use the following command to install the latest version
published on [crates.io]:

```
cargo install --locked dkim-milter
```

During building and installation the option `--features pre-rfc8301` can be
specified to revert cryptographic algorithm and key usage back to before [RFC
8301]: it enables support for the insecure, historic SHA-1 algorithm, and allows
use of RSA key sizes below 1024 bits. Use of this feature is discouraged.

As discussed in the following sections, the default, compiled-in configuration
file path is `/etc/dkim-milter/dkim-milter.conf`. When building DKIM Milter,
this default path can be overridden by setting the environment variable
`DKIM_MILTER_CONFIG_FILE` to the desired path.

The minimum supported Rust version is 1.74.0.

[Rust]: https://www.rust-lang.org
[crates.io]: https://crates.io/crates/dkim-milter
[RFC 8301]: https://www.rfc-editor.org/rfc/rfc8301

## Usage

Once installed, DKIM Milter can be started on the command-line as `dkim-milter`.

Configuration parameters can be set in the default configuration file
`/etc/dkim-milter/dkim-milter.conf`. The mandatory parameter `socket` must be
set in that file.

Invoking `dkim-milter` starts the milter in the foreground. Send a termination
signal to the process or press Control-C to shut the milter down. While the
milter is running, send signal SIGHUP to reload the configuration.

DKIM Milter is usually set up as a system service. Use the provided systemd
service as a starting point. See the included tutorial document for how to
create the system service.

The supported signature algorithms, for both signing and verifying, are
`rsa-sha256` and `ed25519-sha256`. By default, the historic signature algorithm
`rsa-sha1` is not supported, evaluation of such signatures yields a *permerror*
result (RFC 8301; but see feature `pre-rfc8301` above).

## Configuration

The default configuration file is `/etc/dkim-milter/dkim-milter.conf`. The
included manual page [*dkim-milter.conf*(5)] serves as the reference
documentation. (You can view the manual page without installing by passing the
file’s path to `man`: `man ./dkim-milter.conf.5`)

See the included [example configuration] for what a set of configuration files
might look like.

For a hands-on introduction to getting started with DKIM Milter, see the
included [tutorial document].

[*dkim-milter.conf*(5)]: https://codeberg.org/glts/dkim-milter/src/tag/0.2.0-alpha.1/dkim-milter.conf.5
[example configuration]: https://codeberg.org/glts/dkim-milter/src/tag/0.2.0-alpha.1/sample-conf
[tutorial document]: https://codeberg.org/glts/dkim-milter/src/tag/0.2.0-alpha.1/TUTORIAL.md

### Design

DKIM Milter configuration consists of the main configuration file
`dkim-milter.conf`, plus supplementary files or data sources providing
additional table-like configuration.

The main configuration file contains global settings. For signing, configuration
is read from the specified data sources.

Global settings can be overridden for selected inputs through *overrides*
specified in further data sources. Overrides can be applied to connecting
network addresses, recipients (given in the `RCPT TO:` SMTP command), and to
senders (in the *Sender* or *From* headers).

For example, the `recipient_overrides` parameter can be used to specify
configuration overrides for certain message recipients. This allows, for
example, to disable use of the *l=* tag in generated signatures globally, but
enable it for certain recipients only.

This design, with main configuration whose parameters can be overridden with
some granularity, should be flexible enough to implement many configuration
requirements.

### Sign–verify decision

For all messages passed to DKIM Milter, the decision whether the message should
undergo verification or signing is made in the following way.

If a message comes from a *trusted source* and is submitted by an *originator*
that matches a configured *signing sender*, then the message is signed. If a
message comes from an untrusted source, it is verified instead. In other words,
a message from a trusted source is authorised or eligible for signing; it is not
eligible for verification.

A *trusted source* is either a connection from an IP address in
`trusted_networks` (default: loopback), or, if `trust_authenticated_senders` is
set (default: yes), a sender that has been authenticated.

The *originator* of a message is taken from the message’s *Sender* header if
present, else from the message’s *From* header. (Usually, *Sender* is not
present, so the originator will be taken from *From*; however, if *From*
contains multiple mailboxes, *Sender* must be included according to RFC 5322,
and thus the originator will then be taken from *Sender*.)

*Signing senders* are senders (domains or email addresses) for which a signing
key and signing configuration have been set up. They are configured in the data
source referenced by parameter `signing_senders`.

The operating mode (sign-only, verify-only, or automatic per the above
procedure) can also be configured with the `mode` parameter.

### Signing senders

Signing configuration is set up through two configuration parameters pointing to
table-like files (or other data sources, see the following section). These
parameters are `signing_senders` and `signing_keys`:

```
signing_senders = </path/to/signing_senders_file
signing_keys = </path/to/signing_keys_file
```

The main idea for configuring signing is the *signing senders* table (parameter
`signing_senders`). This table links sender email addresses to a concrete
signing configuration:

```
# Sender expression   Domain        Selector   Signing key name
example.org           example.org   sel1       key1
.example.org          example.org   sel2       key2
```

The sender expression `example.org` matches senders with that domain
(`me@example.org`). The sender expression `.example.org` matches both senders
with that domain and also subdomains (`me@subdomain.example.org`). Caution:
*Every* matching sender expression results in an additional DKIM signature for
the message. In above example, messages from `me@example.org` are signed with
two keys because both sender expressions match the address. (Multiple signatures
are primarily useful for double-signing with both an Ed25519 and an RSA key.)

The keys named in the fourth column in the *signing senders* table are listed in
the *signing keys* table (parameter `signing_keys`):

```
# Key name   Key source
key1         </path/to/signing_key1_pem_file
key2         </path/to/signing_key2_pem_file
```

The key source must be a filesystem data source (ie, a path prefixed with `<` or
`file:`) pointing to a PKCS#8 PEM file. The signing key type (RSA or Ed25519)
is detected automatically.

Additional per-signature (ie, per sender expression match) configuration
overrides can be specified in the optional fifth column in the `signing_senders`
file.

Some additional features are briefly mentioned in the remainder of this section.
In the domain column, a single dot `.` copies the domain from the matching
sender address. The two entries in the following listing are equivalent, both
generate tag `d=example.com`:

```
# Sender expression   Domain        ...
example.com           example.com   ...
example.com           .             ...
```

The signing senders table is also where the *signing identity*, that is the *i=*
tag in the generated signature is configured: By default, signatures do not
include the signing identity; use of the `@` character in the domain column
enables the signing identity.

```
# Sender expression   Domain/Identity   ...

example.com           @example.com      ...
example.com           @.                ...
# both => d=example.com, i=@example.com

# Double dot separates i= subdomain from d= domain.
mail.example.com      @mail..example.com
# => d=example.com, i=@mail.example.com

# The local-part before the @ may be included literally.
example.com           user@example.com
# => d=example.com, i=user@example.com

# A dot before the @ copies the sender’s local-part into the i= tag.
example.com           .@example.com
# => d=example.com, i=user@example.com
```

### Data sources

Above, several table-like files were introduced. Those are in fact part of a
more general idea of *data sources*. Some configuration parameters reference
tabular data – a list or set of entries – that will be supplied by a specific
data storage.

Currently three data sources are available: `<` or `slurp:`, reads data from the
filesystem once and then keeps it in memory; `file:`, re-reads data from the
filesystem every time it is needed; (if enabled) `sqlite:`, reads data from an
SQLite database.

The **in-memory filesystem data source** is represented as a file path prefixed
with `<` or `slurp:`.

Example:

```
signing_keys = </path/to/signing-keys
```

When this data source is used, the data is read and validated eagerly at startup
and then kept unchanged in memory until termination (or until reloaded). Lookups
are in-memory, the filesystem is not accessed during operation.

The **live filesystem data source** is represented as a file path prefixed with
`file:`.

Example:

```
signing_keys = file:/path/to/signing-keys
```

With this data source, the data is only read when needed, and not kept in
memory. Changes to the files become active immediately, without needing
reloading or a restart.

What are some uses of the filesystem data sources? You could use `<`
exclusively. The entire configuration will be read eagerly at startup and will
then only exist in memory. If instead you use `file:` everywhere, configuration
is read on demand, ie the filesystem is treated as a database, with changes
being applied automatically and immediately. A further option is to use `<`
throughout, but use `file:` for the signing key files themselves: then all
configuration is kept in memory, but the (sensitive) key material is read into
memory only temporarily for signing and discarded after use.

The **SQLite data source** is represented as an SQLite database URI with prefix
`sqlite:`. This data source is only available with option `--features sqlite` at
build/install time. The table name can be customised by appending `#` followed
by the table name, if needed.

Example:

```
signing_keys = sqlite://mail-config.db#dkim_signing_keys
```

The database schema is documented elsewhere in this project.

In the future, more data sources (SQL, LDAP, …) could be added.

## Key setup

Strictly speaking, key management is out of scope for DKIM Milter. There is,
however, a companion tool [dkimdo] that you can use to do key setup manually.
What follows is a brief introduction.

For signing, DKIM Milter reads *signing keys* (private keys) from files in
PKCS#8 PEM format. This format can be recognised by its beginning line
`-----BEGIN PRIVATE KEY-----`.

Generate an RSA 2048-bit or an Ed25519 private key file `private.pem` with the
following commands, respectively:

```
dkimdo genkey --out-file private.pem rsa
dkimdo genkey --out-file private.pem ed25519
```

These commands create a signing key file for either the RSA or Ed25519 key type.
Each command also prints out the corresponding *DKIM public key record* to the
standard error stream. For example, for RSA the printed record looks something
like the following:

```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCA...
```

The public key record for each signing key must be published in DNS as a TXT
record at domain `<selector>._domainkey.<domain>`. How to do so is specific to
the DNS software and/or DNS provider.

As an example, here is a public key record produced in this manner looked up in
DNS with the `dig` utility. Notice selector `ed25519.2022` and domain
`gluet.ch`:

```
dig +short ed25519.2022._domainkey.gluet.ch txt
```

```
"v=DKIM1; k=ed25519; p=7mOZGVMZF55bgonwHLfOzwlU+UAat5//VJEugD3fyz0="
```

(The Ed25519 public key record above fits in a single text string. The much
larger RSA record is usually spread over several text strings. How such large
TXT records need to be set up depends on DNS software and/or DNS provider.)

A public key record can also be queried using `dkimdo query`. The public key
record can also be generated from an existing signing key using `dkimdo
keyinfo`.

Note that dkimdo output is not at all bespoke or magical, you can just as well
produce the key material using the standard `openssl` utility from the OpenSSL
project.

[dkimdo]: https://crates.io/crates/dkimdo

## Licence

Copyright © 2022–2024 David Bürgin

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
