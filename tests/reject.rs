mod common;

pub use common::*;

use byte_strings::c_str;
use indymilter_test::*;
use log::debug;
use std::io::ErrorKind;

// See signing key in tests/verify_basic/.
const ED25519_PUBKEY: &str = "pEeazcPmc74qbNs51LkKRNqH1A3KLEPFVS4W3E+yl84=";

#[tokio::test]
async fn reject_basic() {
    let mut opts = default_cli_options();
    opts.config_file = Some("tests/reject/dkim-milter.conf".into());

    let config = read_config_with_lookup(opts, |s| match s {
        "sel1._domainkey.example.com." => Box::pin(async {
            Ok(vec![
                // `t=s` forbids subdomains in i= tag, and also in rejection of
                // author signature subdomains.
                Ok(format!("v=DKIM1; t=s; k=ed25519; p={ED25519_PUBKEY}").into_bytes()),
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

    let status = conn.mail(["<you@mail.example.com>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.rcpt(["<me@gluet.ch>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    conn.macros(MacroStage::Data, [("i", "12345ABC")]).await.unwrap();

    let status = conn
        .header(
            "DKIM-Signature",
            "\
v=1; d=example.com; s=sel1; a=ed25519-sha256; t=1683290057;
\th=Subject:To:From:Date; bh=QfiUPNiygQHYiIH2dg2wofoj1TltHmnt/17hJN6XRZY=; b=Rt
\tb4H2HHFhQfLDTKMypz6vpiO4Tida/A31fI5A2CkP80W8NYFr4SPOeNh0NNG2G37bXzMRwBt9ehjov
\tUTeEmAA==",
        )
        .await
        .unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Date", "Fri, 05 May 2023 12:34:31 +0200").await.unwrap();
    assert_eq!(status, Status::Continue);

    // Author subdomain of d= domain not allowed, to be rejected (even though
    // signature is valid).
    let status = conn.header("From", "You <you@mail.example.com>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("To", "Me <me@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Subject", "An example message").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Message-ID", "<3177820507316626058@example.com>").await.unwrap();
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
    assert_eq!(
        status,
        Status::Reject {
            message: Some(c_str!("550 5.7.22 No valid author-matched DKIM signature found").into()),
        }
    );

    debug!("EOM replies: {:?}", actions);

    conn.close().await.unwrap();

    milter.shutdown().await.unwrap();
}
