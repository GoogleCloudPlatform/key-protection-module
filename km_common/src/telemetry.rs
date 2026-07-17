//! Sanitized telemetry infrastructure for Rust KCC FFI boundaries.

use crate::Status;
use std::sync::Once;
use tracing_subscriber::prelude::*;

static PANIC_HOOK: std::sync::Once = std::sync::Once::new();

pub(crate) fn install_sanitized_panic_hook() {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(|_| {}));
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    fn as_str(self) -> &'static str {
        match self {
            Self::GenerateKemKeypair => "generate_kem_keypair",
            Self::DestroyKemKey => "destroy_kem_key",
            Self::EnumerateKemKeys => "enumerate_kem_keys",
            Self::DecapAndSeal => "decap_and_seal",
            Self::GetKemKey => "get_kem_key",
            Self::GenerateBindingKeypair => "generate_binding_keypair",
            Self::DestroyBindingKey => "destroy_binding_key",
            Self::DestroyAllBindingKeys => "destroy_all_binding_keys",
            Self::Open => "open",
            Self::EnumerateBindingKeys => "enumerate_binding_keys",
            Self::GetBindingKey => "get_binding_key",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Error,
    Panic,
}

impl FailureKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Panic => "panic",
        }
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
    ensure_telemetry_initialized();

    tracing::error!(
        target: "rust_kcc",
        operation = failure.operation.as_str(),
        status = failure.status.as_str_name(),
        failure_kind = failure.kind.as_str(),
        service.name = "key_protection_service",
        "kcc_operation_failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
