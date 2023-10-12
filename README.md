# DKIM Milter

🚧 🚧 🚧

***in development***

*Status notice: alpha, in development – but feature-complete. All planned
features for an initial release are available. Lots of
polishing/renaming/pondering, documenting, testing etc. still to be done,
feedback welcome.*

🏗 🏗 🏗

<br>
<br>

DKIM Milter is a milter application that signs or verifies email messages using
the *DomainKeys Identified Mail* (DKIM) protocol. It is meant to be integrated
with a milter-capable MTA (mail server) such as [Postfix]. DKIM is specified in
[RFC 6376].

DKIM Milter is based on the [viadkim] library. Therefore, it inherits the
approach to DKIM used in that library. For example, it fully supports
internationalised email; it is lenient with regard to encoding problems actually
occurring in header values such as invalid UTF-8; it does queries for DKIM
public keys in parallel; it skips unnecessary message body processing; and so
on.

DKIM Milter can be used as a simple alternative to the OpenDKIM milter. Credit
goes to that project, of which I have been a long-time user and which has
inspired some choices made here.

[Postfix]: https://www.postfix.org
[RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
[viadkim]: https://crates.io/crates/viadkim

## Installation

SPF Milter is a [Rust] project. It can be built and/or installed using Cargo.
**Build DKIM Milter from source code with `cargo build` in order to use the
current development state** (initial development; working, but alpha quality).

During building and installation the option `--features pre-rfc8301` can be
specified to revert cryptographic algorithm and key usage back to before [RFC
8301]: it enables support for the insecure, historic SHA-1 algorithm, and allows
use of RSA key sizes below 1024 bits. Use of this feature is strongly
discouraged.

The minimum supported Rust version is 1.65.0.

[Rust]: https://www.rust-lang.org
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
service as a starting point. See the included TUTORIAL document for how to
create the system service.

The supported signature algorithms, for both signing and verifying, are
`rsa-sha256` and `ed25519-sha256`. By default, the historic signature algorithm
`rsa-sha1` is not supported, evaluation of such signatures yields a *permerror*
result (RFC 8301; but see feature `pre-rfc8301` above).

## Configuration

The default configuration file is `/etc/dkim-milter/dkim-milter.conf`. **See the
included example configuration for how to configure the milter, documentation is
not complete yet.**

The included manual page *dkim-milter.conf*(5) serves as the reference
documentation. (You can view the manual page without installing by passing the
file’s path to `man`: `man ./dkim-milter.conf.5`)

For a hands-on introduction to getting started with DKIM Milter, please see the
included TUTORIAL document.

### Design

The configuration is currently entirely file-based. In the future, other data
sources such as an SQL database may be added.

The configuration consists at the minimum of the main configuration file
`dkim-milter.conf`. The main configuration file contains global settings.

The global settings can be overridden for selected inputs through *overrides* in
table-like *override files*. Overrides can be applied to connecting network
addresses, recipients (given in the `RCPT TO:` SMTP command), and to senders (in
the *Sender* or *From* headers).

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
key and signing configuration have been set up. They are configured in the table
referenced by parameter `signing_senders`.

The operating mode (sign-only, verify-only, or automatic per the above
procedure) can also be configured with the `mode` parameter.

### Signing senders

Signing configuration is set up through two configuration parameters pointing to
table-like files. These parameters are `signing_senders` and `signing_keys`.

```
signing_senders = /path/to/signing_senders_file
signing_keys = /path/to/signing_keys_file
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

The key source must currently always be a file path prefixed with `<`, pointing
to a PKCS#8 PEM file. The signing key type (RSA or Ed25519) is detected
automatically.

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

## Key setup

Currently no utilities are provided for key management. However, the `openssl`
utility from OpenSSL 3 can do everything for us. The following tutorial uses
exclusively that tool to do all key setup.

For signing, DKIM Milter reads signing keys (private keys) from files in PKCS#8
PEM format. This format can be recognised by its beginning line
`-----BEGIN PRIVATE KEY-----`.

First, generate an RSA 2048-bit or an Ed25519 private key file `private.pem`
with the following commands, respectively:

```
openssl genpkey -algorithm RSA -out private.pem
openssl genpkey -algorithm ED25519 -out private.pem
```

The corresponding public key for each signing key must be published in DNS in a
special TXT record at domain `<selector>._domainkey.<domain>`.

The minimal format for the TXT record is as follows, where `<key_type>` must be
either `rsa` or `ed25519` for the respective key type, and `<key_data>` must be
the properly encoded public key data as explained in the following paragraph:

```
v=DKIM1; k=<key_type>; p=<key_data>
```

If the key to publish in DNS is of type RSA, use the following command: Extract
the public key from the RSA private key as the final Base64-encoded `<key_data>`
value:

```
openssl pkey -in private.pem -pubout -outform DER |
  openssl base64 -A
```

If the key to publish in DNS is of type Ed25519, use the following command:
First extract the public key from the Ed25519 private key, and then extract and
produce the final Base64-encoded `<key_data>` value:

```
openssl pkey -in private.pem -pubout |
  openssl asn1parse -offset 12 -noout -out /dev/stdout |
  openssl base64 -A
```

For example, here is a key record produced in this manner looked up in DNS with
the `dig` utility. Notice selector `ed25519.2022` and domain `gluet.ch`:

```
dig +short ed25519.2022._domainkey.gluet.ch txt
```

```
"v=DKIM1; k=ed25519; p=7mOZGVMZF55bgonwHLfOzwlU+UAat5//VJEugD3fyz0="
```

(The Ed25519 key record above fits in a single text string. The much larger RSA
key record is usually spread over several text strings. How such large TXT
records need to be set up depends on DNS software and/or DNS provider.)

TODO
For an extended explanation of key generation with the OpenSSL 3 command-line
utility, see `README-keys.md`.

## Licence

Copyright © 2022–2023 David Bürgin

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see <https://www.gnu.org/licenses/>.
