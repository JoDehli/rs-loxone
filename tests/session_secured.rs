//! Secured commands against the scripted mock (visualization code 1234).

use std::time::Duration;

use loxone_mock::{Mock, MockConfig, start};
use rs_loxone::auth::Secret;
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig, SessionError};
use rs_loxone::transport::url::Endpoint;

const DEVICE: &str = "0f1e2d3c-4b5a-6978-ffff403fb0c34b9e";

fn config(mock: &Mock) -> SessionConfig {
    SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        "admin",
        Secret::new("s3cret"),
    )
}

async fn connect(mock: &Mock) -> Session {
    let handler = AsyncHandler(|_e: Event| async {});
    Session::connect(config(mock), handler).await.unwrap()
}

async fn wait_count(mock: &Mock, name: &str, want: usize) -> usize {
    for _ in 0..100 {
        let n = mock.seen().iter().filter(|s| s.as_str() == name).count();
        if n >= want {
            return n;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    mock.seen().iter().filter(|s| s.as_str() == name).count()
}

#[tokio::test]
async fn right_visualization_code_is_accepted() {
    let mock = start(MockConfig::default());
    let session = connect(&mock).await;
    session.send_secured(DEVICE, "1", "1234").await.unwrap();
    assert_eq!(wait_count(&mock, "jdev/sps/ios", 1).await, 1);
    assert_eq!(wait_count(&mock, "jdev/sys/getvisusalt", 1).await, 1);
}

#[tokio::test]
async fn wrong_visualization_code_is_reported() {
    let mock = start(MockConfig::default());
    let session = connect(&mock).await;
    let err = session.send_secured(DEVICE, "1", "0000").await.unwrap_err();
    assert_eq!(err, SessionError::WrongVisuCode);
}

#[tokio::test]
async fn normal_commands_still_work_after_a_secured_command() {
    // The visualization key must not replace the session key or break the salt chain.
    let mock = start(MockConfig::default());
    let session = connect(&mock).await;
    session.send_secured(DEVICE, "1", "1234").await.unwrap();
    session.send_command("jdev/sps/io/AAA/on").await.unwrap();
    assert_eq!(wait_count(&mock, "jdev/sps/io", 1).await, 1);
}

#[tokio::test]
async fn visualization_code_check_answers_without_running_anything() {
    let mock = start(MockConfig::default());
    let session = connect(&mock).await;
    assert!(session.check_visu_code("1234").await.unwrap());
    assert!(!session.check_visu_code("0000").await.unwrap());
    assert_eq!(
        wait_count(&mock, "jdev/sps/checkuservisupwd", 2).await,
        2,
        "both checks reached the Miniserver"
    );
    assert_eq!(
        wait_count(&mock, "jdev/sps/ios", 1).await,
        0,
        "no command was executed"
    );
}
