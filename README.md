# DKIM Milter

### 🚧

### *in development*

### 🏗

<br>

TODO

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

TODO

DKIM Milter must be built or run from source code for now (initial development;
working, but alpha quality).

During building and installation the option `--features pre-rfc8301` can be
specified to revert cryptographic algorithm and key usage back to before [RFC
8301]: it enables support for the insecure, historic SHA-1 algorithm, and allows
use of RSA key sizes below 1024 bits. Use of this feature is strongly
discouraged.

[RFC 8301]: https://www.rfc-editor.org/rfc/rfc8301

## Usage

TODO

Once installed, DKIM Milter can be started on the command-line as `dkim-milter`.

Configuration parameters can be set in the default configuration file
`/etc/dkim-milter/dkim-milter.conf`. The mandatory parameter `socket` must be
set in that file.

DKIM Milter is usually set up as a system service. Use the provided systemd
service as a starting point.

The supported signing algorithms, for both signing and verifying, are
`rsa-sha256` and `ed25519-sha256`. By default, the historic signing algorithm
`rsa-sha1` is not supported, evaluation of such signatures yields a *permerror*
result (RFC 8301; but see feature `pre-rfc8301` above).

## Configuration

TODO

The default configuration file is `/etc/dkim-milter/dkim-milter.conf`. See the
included example configuration for how to configure the milter; documentation is
not complete yet.

### Design

TODO

The configuration is currently entirely file-based.

The configuration consists at the minimum of the main configuration file
`dkim-milter.conf`.

The main configuration file contains global settings.

The global settings can be overridden for certain inputs through *overrides* in
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

### Sign/verify decision

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

### Basic usage

```
socket = inet:localhost:3000
signing_senders = /path/to/signing_senders_file
signing_keys = /path/to/signing_keys_file
authserv_id = mail.example.com
```

The senders for which messages should be signed instead of verified are in the
file configured in `signing_senders`:

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
two keys. (Multiple signatures are primarily useful for double-signing with both
an Ed25519 and an RSA key.)

The keys named in the fourth column in `signing_senders` are listed in the file
configured in `signing_keys`:

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
