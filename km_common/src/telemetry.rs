//! Sanitized telemetry infrastructure for Rust KCC FFI boundaries.

use crate::Status;
use std::sync::{Once, OnceLock};
use tracing_subscriber::prelude::*;

static SERVICE_NAME: OnceLock<String> = OnceLock::new();

pub(crate) fn get_service_name() -> &'static str {
    SERVICE_NAME
        .get()
        .map(|s| s.as_str())
        .unwrap_or("key_protection_service")
}

static PANIC_HOOK: std::sync::Once = std::sync::Once::new();

pub(crate) fn install_sanitized_panic_hook() {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_panic_info| {
            let service_name = get_service_name();
            tracing::error!(
                target: "rust_kcc",
                failure_kind = "panic",
                service.name = service_name,
                "fatal_panic_occurred"
            );
        }));
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationDescriptor {
    pub name: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub enum KccOperation {
    GenerateKemKeypair,
    DestroyKemKey,
    EnumerateKemKeys,
    DecapAndSeal,
    GetKemKey,
    GenerateBindingKeypair,
    DestroyBindingKey,
    DestroyAllBindingKeys,
    Open,
    EnumerateBindingKeys,
    GetBindingKey,
}

impl KccOperation {
    pub const fn descriptor(self) -> OperationDescriptor {
        match self {
            Self::GenerateKemKeypair => OperationDescriptor {
                name: "generate_kem_keypair",
            },
            Self::DestroyKemKey => OperationDescriptor {
                name: "destroy_kem_key",
            },
            Self::EnumerateKemKeys => OperationDescriptor {
                name: "enumerate_kem_keys",
            },
            Self::DecapAndSeal => OperationDescriptor {
                name: "decap_and_seal",
            },
            Self::GetKemKey => OperationDescriptor {
                name: "get_kem_key",
            },
            Self::GenerateBindingKeypair => OperationDescriptor {
                name: "generate_binding_keypair",
            },
            Self::DestroyBindingKey => OperationDescriptor {
                name: "destroy_binding_key",
            },
            Self::DestroyAllBindingKeys => OperationDescriptor {
                name: "destroy_all_binding_keys",
            },
            Self::Open => OperationDescriptor { name: "open" },
            Self::EnumerateBindingKeys => OperationDescriptor {
                name: "enumerate_binding_keys",
            },
            Self::GetBindingKey => OperationDescriptor {
                name: "get_binding_key",
            },
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.descriptor().name
    }
}

impl AsRef<str> for KccOperation {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for KccOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(strum::EnumIter))]
pub(crate) enum FailureKind {
    Error,
    Panic,
}

impl FailureKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Panic => "panic",
        }
    }
}

impl AsRef<str> for FailureKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub(crate) operation: KccOperation,
    pub(crate) status: Status,
    pub(crate) kind: FailureKind,
}

static INIT_TELEMETRY: Once = Once::new();

fn ensure_telemetry_initialized() {
    INIT_TELEMETRY.call_once(|| {
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::stdout),
        );
        tracing::subscriber::set_global_default(subscriber).ok();
    });
}

pub(crate) fn report_failure(failure: Failure) {
    let service_name = get_service_name();

    tracing::error!(
        target: "rust_kcc",
        operation = failure.operation.as_str(),
        status = failure.status.as_str_name(),
        failure_kind = failure.kind.as_str(),
        service.name = service_name,
        "kcc_operation_failed"
    );
}

/// Initializes the process-wide telemetry components inside `km_common`.
///
/// Call this exactly once during process startup, before invoking any KCC operation.
/// Only the first call sets the service name.
///
/// # Safety
/// `service_name_ptr` must point to a valid UTF-8 string buffer of length `service_name_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_manager_init_telemetry(
    service_name_ptr: *const u8,
    service_name_len: usize,
) {
    let name = if service_name_ptr.is_null() || service_name_len == 0 {
        "key_protection_service"
    } else {
        let slice = unsafe { std::slice::from_raw_parts(service_name_ptr, service_name_len) };
        std::str::from_utf8(slice).unwrap_or("key_protection_service")
    };
    let _ = SERVICE_NAME.set(name.to_string());
    ensure_telemetry_initialized();
    install_sanitized_panic_hook();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn sample_failure() -> Failure {
        Failure {
            operation: KccOperation::Open,
            status: Status::DecryptionFailure,
            kind: FailureKind::Error,
        }
    }

    #[test]
    fn test_report_failure_does_not_panic() {
        report_failure(sample_failure());
    }

    const CHILD_ENV: &str = "KM_COMMON_TELEMETRY_TEST_CHILD";

    #[test]
    fn test_report_failure_emits_configured_service_name_json() {
        if std::env::var_os(CHILD_ENV).is_some() {
            let svc = b"my_custom_ws_service";
            unsafe { key_manager_init_telemetry(svc.as_ptr(), svc.len()) };
            report_failure(sample_failure());
            return;
        }

        let output =
            Command::new(std::env::current_exe().expect("test executable should be known"))
                .arg("--exact")
                .arg("telemetry::tests::test_report_failure_emits_configured_service_name_json")
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

        assert!(
            output_text.contains("\"service.name\":\"my_custom_ws_service\"")
                || output_text.contains("\"service.name\": \"my_custom_ws_service\""),
            "Expected configured service name in output: {output_text}"
        );
        assert!(
            output_text.contains("\"operation\":\"open\"")
                || output_text.contains("\"operation\": \"open\""),
            "Expected operation name in output: {output_text}"
        );
        assert!(
            output_text.contains("\"kcc_operation_failed\""),
            "Expected failure message in output: {output_text}"
        );
    }

    #[test]
    fn test_panic_after_init_emits_sanitized_fatal_panic_occurred() {
        const CHILD_ENV_PANIC: &str = "KM_COMMON_PANIC_TEST_CHILD";
        if std::env::var_os(CHILD_ENV_PANIC).is_some() {
            let svc = b"test_panic_service";
            unsafe { key_manager_init_telemetry(svc.as_ptr(), svc.len()) };
            panic!("super_secret_panic_payload_12345");
        }

        let output =
            Command::new(std::env::current_exe().expect("test executable should be known"))
                .arg("--exact")
                .arg("telemetry::tests::test_panic_after_init_emits_sanitized_fatal_panic_occurred")
                .arg("--nocapture")
                .env(CHILD_ENV_PANIC, "1")
                .output()
                .expect("child test process should run");

        assert!(
            !output.status.success(),
            "child should have panicked and failed"
        );

        let output_text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        assert!(
            output_text.contains("\"service.name\":\"test_panic_service\"")
                || output_text.contains("\"service.name\": \"test_panic_service\""),
            "Expected configured service name in panic output: {output_text}"
        );
        assert!(
            output_text.contains("\"failure_kind\":\"panic\"")
                || output_text.contains("\"failure_kind\": \"panic\""),
            "Expected failure_kind=panic in output: {output_text}"
        );
        assert!(
            output_text.contains("\"fatal_panic_occurred\""),
            "Expected fatal_panic_occurred message in output: {output_text}"
        );
        assert!(
            !output_text.contains("super_secret_panic_payload_12345"),
            "Panic payload must not leak into logs: {output_text}"
        );
    }

    #[test]
    fn test_all_operations_descriptor_invariants() {
        use strum::IntoEnumIterator;
        let mut seen = std::collections::HashSet::new();

        for op in KccOperation::iter() {
            let name = op.descriptor().name;
            assert!(!name.is_empty(), "Descriptor name must not be empty");
            assert!(
                name.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "Descriptor name must be snake_case (lowercase ASCII, digits, and underscores)"
            );
            assert!(seen.insert(name), "Descriptor names must be unique");
        }
    }

    #[test]
    fn test_all_operations_report_failure_without_panicking() {
        use strum::IntoEnumIterator;

        for operation in KccOperation::iter() {
            for kind in FailureKind::iter() {
                report_failure(Failure {
                    operation,
                    status: Status::Unspecified,
                    kind,
                });
            }
        }
    }
}
