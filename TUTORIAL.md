# DKIM Milter tutorial

TODO compare with OpenDKIM's ./opendkim/README document

This tutorial demonstrates step by step how to set up a basic DKIM Milter
service. It shows how to configure signing and verifying for a simple
single-domain setup.

While this is a beginner’s tutorial, it does present a real setup, not something
artificial or oversimplified. A setup such as the one here should be perfectly
adequate for most single-domain installations.

Before stepping through this tutorial make sure you have the following ready:

* A working milter-aware MTA (mail server). This tutorial uses Postfix.
* The `openssl` command-line utility.
* The `cargo` Rust tool for building/installing DKIM Milter.
* Your domain, that is the domain that you want to do DKIM signing for. We will
  use *example.com*.

## Install DKIM Milter

First, ensure DKIM Milter is installed. **DKIM Milter has not been released yet,
you need to build from source using `cargo build`.** Make sure the `dkim-milter`
program is on the search path and can be executed.

The command `dkim-milter -V` should print version information.

Towards the end of the tutorial we will set up a system service that runs the
`dkim-milter` command. But before that we need to prepare a working
configuration.

The default configuration file belongs at /etc/dkim-milter/dkim-milter.conf.
Create the directory /etc/dkim-milter and a for now empty file
/etc/dkim-milter/dkim-milter.conf. Usually, you need to run all such commands as
root.

```
mkdir /etc/dkim-milter
touch /etc/dkim-milter/dkim-milter.conf
```

## Generate RSA signing key

DKIM signatures rely on public key cryptography, which is a scheme that uses a
key with a private and a public component. In order to perform signing later,
you first need to generate a private key. We will use an RSA key. You can
generate an RSA signing key using the `openssl` utility from the OpenSSL
project.

First create a keys directory for our signing key in /etc/dkim-milter, and then
run the command that generates an RSA signing key there:

```
mkdir /etc/dkim-milter/keys
openssl genpkey -algorithm RSA -out /etc/dkim-milter/keys/my_rsa_key.pem
```

This is your private, secret key. Protect it well and don’t publish it anywhere!

## Pick a domain and selector

For setting up signing you need to pick a domain and selector. These values will
appear in your DKIM signatures in the *d=* and *s=* tag, respectively. They also
appear in the DNS TXT record location at `<selector>._domainkey.<domain>`. You
must have permission to create this TXT record later.

The domain is your domain, where you have permission to install additional DNS
records. We will use `example.com`.

The selector is a label of your choice. This could be a date, or some other
descriptive or opaque single- or multi-label name. We will use selector
`rsa.2023`.

## Configure signing senders and keys

Let us now look at configuring DKIM Milter. Verification requires no
configuration, but for signing we will have to state for who we want to sign and
how. This is done through the two parameters `signing_keys` and
`signing_senders`. Add the following to /etc/dkim-milter/dkim-milter.conf:

```
signing_keys = /etc/dkim-milter/signing-keys
signing_senders = /etc/dkim-milter/signing-senders
```

/etc/dkim-milter/signing-keys should list the named keys that we want to use for
signing. We generated an RSA signing key earlier and can now add it in this
file. The first column is an arbitrary name, the second is the file path to the
PEM file, prefixed with `<`. Lines starting with `#` are treated as comments and
are ignored:

```
# Key name    Signing key
my_rsa_key    </etc/dkim-milter/keys/my_rsa_key.pem
```

/etc/dkim-milter/signing-senders should list the senders for whom we want to
sign. The first column is the sender expression: This is an expression that will
be matched against the message author in the *From* header. If it matches, then
the message will be signed using the parameters in the remaining columns. DKIM
Milter will not sign anyone’s mail: The signing senders table is only consulted
for authenticated connections or connections from a trusted network.

Add the following in this file:

```
# Sender expression    Domain         Selector    Key name
.example.com           example.com    rsa.2023    my_rsa_key
```

The sender expression `.example.com` matches any email address in the *From*
header where the domain is either *example.com* or a subdomain. The data in the
remaining columns should be familiar now: Your domain *example.com*; the
selector that we settled on earlier; and the name of the signing key in the
`signing_keys` file.

To make a concrete example: When DKIM Milter handles an email message with
header `From: Me Myself <me@example.com>`, it recognises the author domain
example.com. It then consults the signing senders table, finds the matching
entry, and will then generate and insert a signature with tags `d=example.com`,
`s=rsa.2023`, and using key `my_rsa_key` for the cryptographic signature.

## Publish RSA public key

Now that we have signing set up, we need to make sure others can verify our
signatures. With public key cryptography, this requires the public key part to
be published. We need to publish a DKIM public key record (that is, a TXT
record) in DNS at `<selector>._domainkey.<domain>`. In our case, at
`rsa.2023._domainkey.example.com`.

The minimal format of this record is the following, where `<key_data>` is the
public key data:

```
v=DKIM1; k=rsa; p=<key_data>
```

We can extract the public key data from our private signing key using `openssl`:

```
openssl pkey -in /etc/dkim-milter/keys/my_rsa_key.pem -pubout -outform DER | openssl base64 -A
```

This produces a long Base64 string that might look something like
`MIIBIjAN...YQIDAQAB` (without the ellipsis). Paste this into your record, be
sure to copy it entirely and not alter it in any way:

```
v=DKIM1; k=rsa; p=MIIBIjAN...YQIDAQAB
```

Publish this string as a TXT record in DNS at `rsa.2023._domainkey.example.com`.
How exactly this needs to be done depends on your DNS software or DNS provider.
Afterwards check to see if it worked using the `dig` utility:

```
dig +short rsa.2023._domainkey.example.com. txt
```

```
"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqR9XCFPJhKWt7t4D0nXJrKINF8ZorIliAEV8fyyMjFPNR8tPzjRJw/TvSML6s+034jRIZ10k66k80s1ayGj0TQDy" "iGbiebQanzGz2VNRLeUPow0dBOjQfkuhKuKLmu9xljnuIdT8LEQbBOBk0hr4peUUj8wxk6OuWsF1Fcpis3HEjOnqZn1cPe9sSS43w6ex9PGuhLddWCfgeBmTtMbCwd1MPA0CVTkwD3vG/irkOVYb2o" "0racJ1EMIQD8FjnExJpFFK0QbExT334BVH+tHUPXc7etoiKMKqSETVb0XtQvTSkowE8qXO8IXOxkzW2cZLP+yU5YPSikwoKcY/tJlCYQIDAQAB"
```

Look closely at the output: notice how the very large record has been split into
three character strings. Logically this represents a single string but DNS
limitations require a large string to be segmented into smaller parts. Again,
how this needs to be set up depends on the DNS software that you use. But the
final outcome should look similar to what is shown above.

## Set up systemd service

Now, we would like to run DKIM Milter as a system service. One easy way to do
this is to use a systemd service. It is good practice not to run such services
as the superuser, but use a dedicated system user instead. So let’s create a
`dkim-milter` system user. For example, on Debian and Ubuntu:

```
sudo adduser --system --home /var/lib/dkim-milter --group dkim-milter
```

With the dedicated user available, let’s use the opportunity to further secure
the private key by giving it to to this user with permissions 0400.

```
chown dkim-milter /etc/dkim-milter/keys/my_rsa_key.pem
chmod 0400 /etc/dkim-milter/keys/my_rsa_key.pem
```

Now let’s create the service at `/etc/systemd/system/dkim-milter.service` with
the following content. This service uses the executable at path
`/usr/sbin/dkim-milter`, make sure you have installed the program at this exact
path.

```
[Unit]
Description=DKIM Milter
Documentation=man:dkim-milter(8) man:dkim-milter.conf(5)
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=dkim-milter
ExecStart=/usr/sbin/dkim-milter
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Almost there! Before starting the service, now the mandatory parameter `socket`
must be set, too. This is the socket through which the MTA will talk to the DKIM
Milter service. A straightforward choice is a TCP socket, for example at port
3000. Add it to /etc/dkim-milter/dkim-milter.conf:

```
socket = inet:localhost:3000
```

Now enable and start the service:

```
systemctl enable --now dkim-milter
```

The command `systemctl status dkim-milter` should now show the DKIM Milter
service as running.

## Integration with Postfix

Finally, in order to allow the MTA to speak to our new DKIM Milter service, we
must inform it of the service’s presence by adding the listening socket in
Postfix’s configuration.

Above, we picked port 3000, so that is where DKIM Milter is awaiting requests
from Postfix. Add this socket in `smtpd_milters` and `non_smtpd_milters` in
Postfix’s main configuration file /etc/postfix/main.cf:

```
smtpd_milters = inet:localhost:3000
non_smtpd_milters = $smtpd_milters
```

If you already have other milters listed there, then add the socket where
appropriate: For example, after any SPF milter and before any DMARC milter. If
you do have an SPF milter before the new DKIM milter, and the SPF milter does
itself add *Authentication-Results* headers with verification results, then you
should add the following parameter in /etc/dkim-milter/dkim-milter.conf, else
those headers will be deleted by DKIM Milter.

```
delete_incoming_authentication_results = no
```

Don’t forget to reload Postfix after editing its configuration, `systemctl
reload postfix`.

## Summary

Your mail server is now signing and verifying mail according to the DKIM spec.
Congratulations!

As a summary, let us list briefly the files and directories that we created
during this tutorial.


```
tree /etc/dkim-milter
```

```
/etc/dkim-milter
├── dkim-milter.conf
├── keys
│   └── my_rsa_key.pem
├── signing-keys
└── signing-senders

1 directory, 4 files
```

The final configuration /etc/dkim-milter/dkim-milter.conf:

```
socket = inet:localhost:3000
signing_keys = /etc/dkim-milter/signing-keys
signing_senders = /etc/dkim-milter/signing-senders
# and optionally:
delete_incoming_authentication_results = no
```

The signing key /etc/dkim-milter/keys/my_rsa_key.pem:

```
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCpH1cIU8mEpa3u
3gPSdcmsog0XxmisiWIARXx/LIyMU81Hy0/ONEnD9O9Iwvqz7TfiNEhnXSTrqTzS
zVrIaPRNAPKIZuJ5tBqfMbPZU1Et5Q+jDR0E6NB+S6Eq4oua73GWOe4h1PwsRBsE
4GTSGvil5RSPzDGTo65awXUVymKzccSM6epmfVw972xJLjfDp7H08a6Et11YJ+B4
GZO0xsLB3Uw8DQJVOTAPe8b+KuQ5VhvajStpwnUQwhAPwWOcTEmkUUrRBsTFPffg
FUf60dQ9dzt62iIowqpIRNVvRe1C9NKSjATypc7whc7GTNbZxks/7JTlg9KKTCgp
xj+0mUJhAgMBAAECggEAAJ4DWh29qxr0cX4skQWiZ7uT7Qe5qTMLaTU3twpbZTX3
VmUt4HKZCBK+VpN1GSfjC8OddcidjlFg3iNXGusEpL0NlY08E34CeJ0koxT6c26e
Be4h4msj2yklIIAhCq7H6SijF4skpDf3qgb0YT6tVIQrdPqlneyDkfPZrLufTHi6
3g7TyEdE72ZtHLFbfUrTrf/nBboIJvP11JO36Y5B4CjBIS43mwtYh4Du7pLlBPF0
PzQusyCovW+tHvMSGZvEgo5Jy/FCxYQTW03zUL3eLYpWpf3tNr1MSJJY8Nv6hGyz
cHRpG7FRv90OdhPKORuhqwJ1VT0SRCi78g1PUfwFgQKBgQDJK7bMIeMUjk8hJH+J
bTCBOZTI0UrlkPW9iXwRa2ZMf0OewVOvlbDfrwv1xpQiYF+KLCe5fGLtz7W84V5l
UyliNCg2VZ3YNOPXHRXGNqs/hUr3rUpqZLYIqEPG2IQSmg5OAZgbIIaHqcAhk49W
cB8OgxBbxgE4AoQTOp2IuCjSQQKBgQDXN4R/WcCmF3V4CPRSiLLBVwCPrAHnK+Ip
2Vuhbtsmi8anurQzXOrEzE75i8rVjc3C8jwTE1GfXgkeq1ay5/LQnam9V0r+mK02
OpvXc4yLlhtW6k/h3VKCl6LbqaPzg4qNOsEkG6X/CXAsjaWRHIweJnuqB1STdeuw
0spl/3woIQKBgBLCF757HnCJQImnnJjU7KPwGZaMJX64gKGW01HQgO57I3QHNOV3
gNGqweO+C4wVDnOU4HNkTNk9+AVPwnySP5afpGxEmX5SmDgzxxb/fAJlTHNB3mGD
WJIAFqnRAKe3Y8QUU/mbk8/MnVTELKZzuAGjaQAVu4FcgrJEUfIwseXBAoGAB4sJ
mNETgH7H/joKHi5uXXpoKaD0vB58oczdek4BXlt9zfksQbSbAeTLS9HLfSqoMJH+
6wg9TyGjnjCRLFoW15r/DQTXOw8s2v644ZdKMMZFFQnHXPo93xfjfGF4vps4qvSJ
OnPBoKu7A8S/LdPbUV817GKvYy+54AuzTlnjByECgYBCf3cn/lFWgW7KbApT31/5
qefw3X77dPT1ETySVcvGcw9l8vSjUIaIJWRDwvH7gBeujkIWeWH1jmOXlwxZbNvU
BnW7tZOZM0UVB2LazfUl8sHTN5RngeUHl4K0tM+ZyMfpO0lo6NSxly6LNg8aiAws
/KGU+0GJqLMcWsdLGa9x0Q==
-----END PRIVATE KEY-----
```

The /etc/dkim-milter/signing-keys table:

```
# Key name    Signing key
my_rsa_key    </etc/dkim-milter/keys/my_rsa_key.pem
```

The /etc/dkim-milter/signing-senders table:

```
# Sender expression    Domain         Selector    Key name
.example.com           example.com    rsa.2023    my_rsa_key
```

Further files that we used were:

* /usr/sbin/dkim-milter – the executable
* /etc/systemd/system/dkim-milter.service – the systemd service

We also touched the Postfix configuration file /etc/postfix/main.cf.

We also added a TXT record in DNS at `rsa.2023._domainkey.example.com`.
