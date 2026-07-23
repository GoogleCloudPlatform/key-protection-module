pub mod keymanager;
pub use keymanager as proto;

pub use proto::Status;
pub use telemetry::KccOperation;

pub const MAX_ALGORITHM_LEN: usize = 128;
pub const MAX_PUBLIC_KEY_LEN: usize = 2048;

const REDACTED: &str = "[REDACTED]";

pub(crate) fn fmt_redacted(f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(REDACTED)
}

impl std::error::Error for Status {}
impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

fn ffi_call_with_reporter<F, R>(operation: KccOperation, f: F, reporter: R) -> Status
where
    F: FnOnce() -> Result<(), Status>,
    R: FnOnce(telemetry::Failure),
{
    telemetry::install_sanitized_panic_hook();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => Status::Success,
        Ok(Err(status)) => {
            reporter(telemetry::Failure {
                operation,
                status,
                kind: telemetry::FailureKind::Error,
            });
            status
        }
        Err(_) => {
            reporter(telemetry::Failure {
                operation,
                status: Status::InternalError,
                kind: telemetry::FailureKind::Panic,
            });
            Status::InternalError
        }
    }
}

/// Safely executes an FFI closure and queues one sanitized event on error or panic.
pub fn ffi_call<F>(operation: KccOperation, f: F) -> Status
where
    F: FnOnce() -> Result<(), Status>,
{
    ffi_call_with_reporter(operation, f, telemetry::report_failure)
}

fn ffi_call_i32_with_reporter<F, R>(operation: KccOperation, f: F, reporter: R) -> i32
where
    F: FnOnce() -> Result<i32, Status>,
    R: FnOnce(telemetry::Failure),
{
    telemetry::install_sanitized_panic_hook();
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(val)) => val,
        Ok(Err(status)) => {
            reporter(telemetry::Failure {
                operation,
                status,
                kind: telemetry::FailureKind::Error,
            });
            -(status as i32)
        }
        Err(_) => {
            reporter(telemetry::Failure {
                operation,
                status: Status::InternalError,
                kind: telemetry::FailureKind::Panic,
            });
            -(Status::InternalError as i32)
        }
    }
}

/// Safely executes an integer-returning FFI closure and queues one sanitized failure event.
pub fn ffi_call_i32<F>(operation: KccOperation, f: F) -> i32
where
    F: FnOnce() -> Result<i32, Status>,
{
    ffi_call_i32_with_reporter(operation, f, telemetry::report_failure)
}

pub mod crypto;
pub mod key_types;
pub mod protected_mem;
mod telemetry;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_success_does_not_report_a_failure() {
        let mut failure = None;
        let status = ffi_call_with_reporter(
            KccOperation::GenerateBindingKeypair,
            || Ok(()),
            |event| failure = Some(event),
        );

        assert_eq!(status, Status::Success);
        assert_eq!(failure, None);
    }

    #[test]
    fn ffi_error_reports_one_typed_failure() {
        let mut failure = None;
        let status = ffi_call_with_reporter(
            KccOperation::Open,
            || Err(Status::DecryptionFailure),
            |event| failure = Some(event),
        );

        assert_eq!(status, Status::DecryptionFailure);
        assert_eq!(
            failure,
            Some(telemetry::Failure {
                operation: KccOperation::Open,
                status: Status::DecryptionFailure,
                kind: telemetry::FailureKind::Error,
            })
        );
    }
}
