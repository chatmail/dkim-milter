mod common;

pub use common::*;

use dkim_milter::*;
use indymilter::MacroStage;
use indymilter_test::*;
use log::debug;

#[tokio::test]
async fn basic_sign_both() {
    let mut opts = default_cli_options();
    opts.config_file = Some("tests/sign_both/dkim-milter.conf".into());

    let config = Config::read(opts).await.unwrap();

    let milter = DkimMilter::spawn(config).await.unwrap();

    let mut conn = TestConnection::open(milter.addr()).await.unwrap();

    conn.macros(MacroStage::Connect, [("j", "localhost")]).await.unwrap();

    let status = conn.connect("client.gluet.ch", [127, 0, 0, 10]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.mail(["<me@gluet.ch>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.rcpt(["<postfix-users@postfix.org>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    conn.macros(MacroStage::Data, [("i", "1234567ABC")]).await.unwrap();

    let status = conn.header("Date", "Fri, 18 Nov 2022 13:02:55 +0000").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("From", "Proff <me@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("To", "postfix-users@postfix.org").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Subject", "Milter on loopback address").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Message-ID", "<eef27026-8d2e-11ed-bcc6-7b74040beb8d@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.eoh().await.unwrap();
    assert_eq!(status, Status::Continue);

    let body = "\
What happens when a milter listens on
a loopback address?

Thank you,
";
    let body = body.replace('\n', "\r\n");
    let status = conn.body(body).await.unwrap();
    assert_eq!(status, Status::Continue);

    let (actions, status) = conn.eom().await.unwrap();
    assert_eq!(status, Status::Continue);

    debug!("EOM replies: {:?}", &actions.replies);

    conn.close().await.unwrap();

    milter.shutdown().await.unwrap();
}
