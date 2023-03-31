mod common;

pub use common::*;

use dkim_milter::*;
use indymilter::MacroStage;
use indymilter_test::*;
use tracing::debug;

#[tokio::test]
#[ignore = "depends on live DNS records"]
async fn basic_verify_rsa() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut opts = CliOptions::default();
    opts.config_file = "tests/dkim-milter.conf".into();
    let config = Config::read(opts).await.unwrap();

    let milter = DkimMilter::spawn(config).await.unwrap();

    let mut conn = TestConnection::open(milter.addr()).await.unwrap();

    conn.macros(MacroStage::Connect, [("j", "localhost")]).await.unwrap();

    let status = conn.connect("client.gluet.ch", [123, 123, 123, 123]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.mail(["<david@gluet.ch>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.rcpt(["<postfix-users@postfix.org>"]).await.unwrap();
    assert_eq!(status, Status::Continue);

    conn.macros(MacroStage::Data, [("i", "1234567ABC")]).await.unwrap();

    let status = conn.header("DKIM-Signature", "\
v=1; a=rsa-sha256; c=relaxed/simple; d=gluet.ch; s=2020;
	t=1672918473; x=1673350473;
	bh=ClG2e7tISzJYrrW94FA6IzY2FsIkk9yxZN1eIC8Sthc=;
	h=Date:From:To:Subject:From;
	b=sJ1zOxhZor4mD/ZS6ykGu4ELt+F3Hc9O5KooeHl3vIo+5+gzyJQddGHL6FMXuzRR7
	 6P2RIBwERuhbECpwnlTXkMPeUdAlgszR0/EbUTLrAkZVM7oYbGOzUezg3Z3jIFPDA8
	 N1FbUr1KnrKFUtIYJ4I/c9mD7ncvH9lUetInpcfpVPmnc2jzAi4gUXnwb6/kjtiAgD
	 mn4cEKUwV6l81G8B/uqAFZoqX+hcG2TWr14/y1h5pX0eyq0zHD5QKecfLG0sRwE3jk
	 cKVpj/ag6ICKdM4Vp2GfaC6DcOs7f2lEINcZQFVr1ZIgiVDunnlS+ORlZFSoNEM6jj
	 GjmlJg7h3fbRg==").await.unwrap();
    assert_eq!(status, Status::Continue);

    // plus 1 broken sig:
    let status = conn.header("DKIM-Signature", "\
v=1; a=rsa-sha1; c=relaxed; d=gluet.ch; s=2020; bh=5KNWxtGs;
 h=Date:From:To:Subject:From; b=jVCK").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Date", "Thu, 5 Jan 2023 12:34:31 +0100").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("From", "David =?utf-8?Q?B=C3=BCrgin?= <dbuergin@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("To", "postfix-users@postfix.org").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Subject", "Find out whether a sender is authenticated in a milter?").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.header("Message-ID", "<Y7a1xzMfcRBVLwXP@gluet.ch>").await.unwrap();
    assert_eq!(status, Status::Continue);

    let status = conn.eoh().await.unwrap();
    assert_eq!(status, Status::Continue);

    let body = "\
Previously in a milter I have used presence of sendmail macro
‘{auth_authen}’ to decide whether a sender is authenticated.

Now, in another milter I am using presence of macro ‘{auth_type}’ to
make that decision.

What is the recommended way of telling whether a sender is authenticated
using sendmail macros? Is one of the auth macros a better choice, or is
it the case that if one is defined all of them are?

Thank you.
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
