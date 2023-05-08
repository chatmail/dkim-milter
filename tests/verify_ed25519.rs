mod common;

pub use common::*;

use dkim_milter::*;
use indymilter::MacroStage;
use indymilter_test::*;
use std::io::ErrorKind;
use log::debug;

#[tokio::test]
async fn basic_verify_ed25519() {
    let mut opts = default_cli_options();
    opts.config_file = Some("tests/verify_ed25519/dkim-milter.conf".into());

    let config = Config::read_with_lookup(opts, |s| match s {
        "sel1._domainkey.gluet.ch." => Box::pin(async {
            Ok(vec![
                Ok(b"v=DKIM1; un=usable".to_vec()),
                Ok(b"v=DKIM1; k=ed25519; p=pEeazcPmc74qbNs51LkKRNqH1A3KLEPFVS4W3E+yl84=".to_vec()),
            ])
        }),
        _ => Box::pin(async { Err(ErrorKind::NotFound.into()) }),
    })
    .await
    .unwrap();

    let milter = DkimMilter::spawn(config).await.unwrap();

    let mut conn = TestConnection::open(milter.addr()).await.unwrap();

    conn.macros(MacroStage::Connect, [("j", "mail.gluet.ch")])
        .await
        .unwrap();

    let status = conn
        .connect("client.gluet.ch", [123, 123, 123, 123])
        .await
        .unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.mail(["<david@gluet.ch>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.rcpt(["<you@example.com>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    conn.macros(MacroStage::Data, [("i", "1234567ABC")]).await.unwrap();

    let status = conn
        .header(
            "DKIM-Signature",
            "\
v=1; d=gluet.ch; s=sel1; a=ed25519-sha256; t=1683290057;
	h=Subject:To:From:Date; bh=TPLZoO7LI/6wMUlqqQgxYBvNapYR50Z8yEvX4m9FcFA=; b=SS
	lQlojiI41NdfofRli7WSo9azvPiZD9BrE99HeUzUn6MVFhuP8tF7vAznp+k8SYaBo8pWwICfaXo8N
	PKCekAA==",
        )
        .await
        .unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Date", "Fri, 05 May 2023 12:34:31 +0200").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("From", "David <dbuergin@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("To", "You <you@example.com>").await.unwrap();
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

Adieu ~

Dave
";
    let body = body.replace('\n', "\r\n");
    let status = conn.body(body).await.unwrap();
    assert_eq!(status, Status::Continue);

    let (actions, status) = conn.eom().await.unwrap();
    assert_eq!(status, Status::Continue);

    debug!("EOM replies: {:?}", &actions.replies);

    assert!(actions.has_insert_header(
        0,
        "Authentication-Results",
        " example.gluet.ch;\n\tdkim=pass header.d=gluet.ch header.b=SSlQloji",
    ));

    conn.close().await.unwrap();

    milter.shutdown().await.unwrap();
}
