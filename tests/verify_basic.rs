mod common;

pub use common::*;

use indymilter_test::*;
use log::debug;
use std::io::ErrorKind;

// See signing key in tests/verify_basic/.
const ED25519_PUBKEY: &str = "pEeazcPmc74qbNs51LkKRNqH1A3KLEPFVS4W3E+yl84=";

#[tokio::test]
async fn verify_basic_ed25519() {
    let mut opts = default_cli_options();
    opts.config_file = Some("tests/verify_basic/dkim-milter.conf".into());

    let config = read_config_with_lookup(opts, |s| match s {
        "sel1._domainkey.example.com." => Box::pin(async {
            Ok(vec![
                Ok(b"v=DKIM1; un=usable".to_vec()),
                Ok(format!("v=DKIM1; k=ed25519; p={ED25519_PUBKEY}").into_bytes()),
            ])
        }),
        _ => Box::pin(async { Err(ErrorKind::NotFound.into()) }),
    })
    .await
    .unwrap();

    let milter = DkimMilter::spawn(config).await.unwrap();

    let mut conn = TestConnection::open(milter.addr()).await.unwrap();

    conn.macros(MacroStage::Connect, [("j", "mail.gluet.ch")]).await.unwrap();

    let status = conn.connect("client.example.com", [123, 123, 123, 123]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.mail(["<you@example.com>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.rcpt(["<me@gluet.ch>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    conn.macros(MacroStage::Data, [("i", "12345ABC")]).await.unwrap();

    let status = conn
        .header(
            "DKIM-Signature",
            "\
v=1; d=example.com; s=sel1; a=ed25519-sha256; t=1683290057;
\th=Subject:To:From:Date; bh=QfiUPNiygQHYiIH2dg2wofoj1TltHmnt/17hJN6XRZY=; b=3k
\tfDebVrMYsVzQ4/kMmcNCrCm6FJKGSaxrCbw0MUmw54F6Z1AiqGSXuJtv05RnF6nNovWsG+qJ47UWg
\ttjBrVDw==",
        )
        .await
        .unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Date", "Fri, 05 May 2023 12:34:31 +0200").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("From", "You <you@example.com>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("To", "Me <me@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Subject", "An example message").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Message-ID", "<3177820507316626058@example.com").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.eoh().await.unwrap();
    assert_eq!(status, Status::Continue);

    let body = "\
Hello!

This is a plain example message for your convenience.
Enjoy signing it.

Cheers,
L
";
    let body = body.replace('\n', "\r\n");
    let status = conn.body(body).await.unwrap();
    assert_eq!(status, Status::Continue);

    let (actions, status) = conn.eom().await.unwrap();
    assert_eq!(status, Status::Continue);

    debug!("EOM replies: {:?}", actions);

    assert!(actions.has_insert_header(
        0,
        "Authentication-Results",
        " example.gluet.ch;\n\
        \tdkim=pass header.d=example.com header.i=@example.com\n\
        \t header.a=ed25519-sha256 header.s=sel1 header.b=3kfDebVr",
    ));

    conn.close().await.unwrap();

    milter.shutdown().await.unwrap();
}

#[tokio::test]
async fn verify_i18n_ed25519() {
    let mut opts = default_cli_options();
    opts.config_file = Some("tests/verify_basic/dkim-milter.conf".into());

    let config = read_config_with_lookup(opts, |s| match s {
        "sel1._domainkey.xn--um8h.example.xn--fiqs8s." => Box::pin(async {
            Ok(vec![
                Ok(format!("v=DKIM1; k=ed25519; p={ED25519_PUBKEY}").into_bytes()),
            ])
        }),
        _ => Box::pin(async { Err(ErrorKind::NotFound.into()) }),
    })
    .await
    .unwrap();

    let milter = DkimMilter::spawn(config).await.unwrap();

    let mut conn = TestConnection::open(milter.addr()).await.unwrap();

    conn.macros(MacroStage::Connect, [("j", "mail.gluet.ch")]).await.unwrap();

    let status = conn.connect("client.xn--um8h.example.xn--fiqs8s", [123, 123, 123, 123]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.mail(["<you@🏠.Example.中国>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.rcpt(["<me@gluet.ch>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    conn.macros(MacroStage::Data, [("i", "12345ABC")]).await.unwrap();

    let status = conn
        .header(
            "DKIM-Signature",
            "\
v=1; d=🏠.Example.中国; s=sel1; a=ed25519-sha256; t=1683290057;
\th=Subject:To:From:Date; bh=oGD+lBgqBFfbFptxIFbgjnMIcXyRbRymCkCinFc/BKE=; b=El
\tpQhEsvwdepc8IDzklQXnL6WllSSpebQ0LCL7PGyEVUhmd90TTTRMKn3tauhAykRg4fil4C1n2PWvM
\tjVVQ8DQ==",
        )
        .await
        .unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Date", "Fri, 05 May 2023 12:34:31 +0200").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("From", "You <you@🏠.Example.中国>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("To", "Me <me@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Subject", "An example message").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Message-ID", "<3177820507316626058@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.eoh().await.unwrap();
    assert_eq!(status, Status::Continue);

    let body = "\
Hello!

This is an 𝔈xample 𝔐essage for your convenience.
Enjoy signing it.

Adieu ~～～～
L
";
    let body = body.replace('\n', "\r\n");
    let status = conn.body(body).await.unwrap();
    assert_eq!(status, Status::Continue);

    let (actions, status) = conn.eom().await.unwrap();
    assert_eq!(status, Status::Continue);

    debug!("EOM replies: {:?}", actions);

    assert!(actions.has_insert_header(
        0,
        "Authentication-Results",
        " example.gluet.ch;\n\
        \tdkim=pass header.d=🏠.Example.中国 header.i=@🏠.Example.中国\n\
        \t header.a=ed25519-sha256 header.s=sel1 header.b=ElpQhEsv",
    ));

    conn.close().await.unwrap();

    milter.shutdown().await.unwrap();
}
