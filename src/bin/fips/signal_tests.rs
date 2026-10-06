//! A stop signal that arrives before the shutdown future is first polled.
//!
//! The daemon builds its shutdown future at the top of `main` and polls it
//! only once start-up is under way. A SIGTERM or SIGINT delivered in between
//! must still complete the future rather than take the default action, which
//! kills the process outright (or, as PID 1 in a container, is discarded).
//!
//! Each test raises the signal in a child process, because a signal that is
//! not handled ends whichever process receives it, and a registered handler
//! stays registered for the life of the process.

use std::process::Command;
use std::time::Duration;

/// Environment variable that tells a re-run test binary to act as the child.
const CHILD: &str = "FIPS_TEST_SHUTDOWN_SIGNAL_CHILD";

/// Re-run this test binary for `test` alone and check that the child took
/// the signal through the shutdown future, naming `signal` in its log.
fn run_child(test: &str, signal: &str) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads", "1"])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child did not survive {signal} ({}):\n{stdout}\n{stderr}",
        output.status
    );
    // libtest exits 0 when the filter selects nothing, so require that the
    // child actually ran the test.
    assert!(
        stdout.contains("1 passed"),
        "child did not run the test:\n{stdout}\n{stderr}"
    );
    assert!(
        stdout.contains("Shutdown signal handler installed"),
        "child did not log the handler installation:\n{stdout}"
    );
    assert!(
        stdout.contains("Shutdown signal received") && stdout.contains(&format!("signal={signal}")),
        "child did not log receiving {signal}:\n{stdout}"
    );
}

/// In the child: build the shutdown future, raise `signum` before polling
/// it, then require the future to complete.
fn raise_before_poll(signum: libc::c_int) {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_ansi(false)
        .try_init();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let shutdown = crate::foreground_shutdown_signal();
        // SAFETY: raise(3) only delivers a signal to the calling thread.
        assert_eq!(unsafe { libc::raise(signum) }, 0, "raise failed");
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("the shutdown future did not complete after the signal");
    });
}

#[test]
fn sigterm_raised_before_the_shutdown_future_is_polled_completes_it() {
    if std::env::var_os(CHILD).is_some() {
        raise_before_poll(libc::SIGTERM);
        return;
    }
    run_child(
        "signal_tests::sigterm_raised_before_the_shutdown_future_is_polled_completes_it",
        "SIGTERM",
    );
}

#[test]
fn sigint_raised_before_the_shutdown_future_is_polled_completes_it() {
    if std::env::var_os(CHILD).is_some() {
        raise_before_poll(libc::SIGINT);
        return;
    }
    run_child(
        "signal_tests::sigint_raised_before_the_shutdown_future_is_polled_completes_it",
        "SIGINT",
    );
}
