use km_common::{KccOperation, Status, ffi_call};
use std::process::Command;

const CHILD_ENV: &str = "KM_COMMON_PANIC_SANITIZATION_CHILD";
const SECRET_SENTINEL: &str = "panic-secret-sentinel-7a4f1d";

#[test]
fn caught_ffi_panics_do_not_emit_sensitive_diagnostics() {
    if std::env::var_os(CHILD_ENV).is_some() {
        let status = ffi_call(KccOperation::Open, || panic!("{SECRET_SENTINEL}"));
        assert_eq!(status, Status::InternalError);
        return;
    }

    let output = Command::new(std::env::current_exe().expect("test executable should be known"))
        .arg("--exact")
        .arg("caught_ffi_panics_do_not_emit_sensitive_diagnostics")
        .arg("--nocapture")
        .env(CHILD_ENV, "1")
        .output()
        .expect("child test process should run");

    assert!(
        output.status.success(),
        "child failed: stdout={:?}, stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output_text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output_text.contains(SECRET_SENTINEL));
    assert!(!output_text.contains("panicked at"));
    assert!(!output_text.contains("stack backtrace"));
    assert!(output_text.contains("kcc_operation_failed"));
}
