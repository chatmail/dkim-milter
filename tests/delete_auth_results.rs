mod common;

pub use common::*;

use dkim_milter::*;
use indymilter::MacroStage;
use indymilter_test::*;
use std::io::ErrorKind;
use log::debug;

#[tokio::test]
async fn delete_auth_results() {
    let mut opts = default_cli_options();
    opts.config_file = Some("tests/delete_auth_results/dkim-milter.conf".into());

    let config = Config::read_with_lookup(opts, |_| {
        Box::pin(async { Err(ErrorKind::NotFound.into()) })
    })
    .await
    .unwrap();

    let milter = DkimMilter::spawn(config).await.unwrap();

    let mut conn = TestConnection::open(milter.addr()).await.unwrap();

    conn.macros(MacroStage::Connect, [("j", "mail.gluet.ch")]).await.unwrap();

    let status = conn.connect("client.gluet.ch", [123, 123, 123, 123]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.mail(["<from@example.org>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.rcpt(["<you@example.com>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    conn.macros(MacroStage::Data, [("i", "1234567ABC")]).await.unwrap();

    let status = conn.header("Authentication-Results", "\
(different authserv-id:) myhost.org
  1; spf=pass smtp.mailfrom=example.org").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Authentication-Results", "\
(invalid authserv-id:) mail.gluet.ch/1234;
  spf=pass smtp.mailfrom=example.org").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Authentication-Results", "\
(unusual but legal
  comment) \"mail.G\\luet.ch\" (<- attempt to bypass deletion!); spf=pass
  smtp.mailfrom=example.org").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.eoh().await.unwrap();
    assert_eq!(status, Status::Continue);

    let body = "\
Hello!
Goodbye!
";
    let body = body.replace('\n', "\r\n");
    let status = conn.body(body).await.unwrap();
    assert_eq!(status, Status::Skip);

    let (actions, status) = conn.eom().await.unwrap();
    assert_eq!(status, Status::Continue);

    debug!("EOM replies: {:?}", &actions.replies);

    assert!(actions.has_delete_header("Authentication-Results", 3));

    assert!(actions.has_insert_header(
        0,
        "Authentication-Results",
        " mail.gluet.ch; dkim=none"
    ));

    conn.close().await.unwrap();

    milter.shutdown().await.unwrap();
}
