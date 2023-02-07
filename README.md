# DKIM Milter

<br>

🚧

***experimental, in development***

🏗

<br>

TODO

DKIM Milter is a milter application that signs or verifies email messages using
the *DomainKeys Identified Mail* (DKIM) protocol. DKIM is specified in [RFC
6376].

DKIM milter is based on the [viadkim] library. Therefore, it inherits the
approach to DKIM used in that library. For example, it is lenient with regard to
encoding problems actually occurring in header values: a header value containing
invalid UTF-8 bytes is not a problem, but processed transparently as a byte
string, etc.

DKIM Milter can be used as a simple alternative to the OpenDKIM milter. Credit
goes to that project, of which I have been a long-time happy user and which has
inspired some choices made here.

[RFC 6376]: https://www.rfc-editor.org/rfc/rfc6376
[viadkim]: https://crates.io/crates/viadkim

## Installation

TODO

DKIM Milter must be built or run from source code for now (initial development,
alpha quality).

A source checkout of viadkim in a sibling directory is also required.

## Usage

TODO

For all messages passed to this milter, the decision whether the message should
undergo verification or signing is made in the following way: If the message
comes from a local IP address or is submitted by an authenticated sender then
the message is *authorised* for signing; if the message is authorised and the
email address in the message’s *From* header matches a configured *signing
sender*, then the message is signed. In all other cases, the message is verified
instead.

The supported signature algorithms, for both signing and verifying, are
`rsa-sha256` and `ed25519-sha256`. The historic signature algorithm `rsa-sha1`
is not supported, evaluation of such signatures yields a *permerror* result (RFC
8301).

## Configuration

TODO

The default configuration file is `/etc/dkim-milter/dkim-milter.conf`.

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
two keys.

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
overrides are in `signature_settings` (not implemented).

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
this program. If not, see https://www.gnu.org/licenses/.
