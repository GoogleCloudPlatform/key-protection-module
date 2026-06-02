//! Memory protection utilities using `memfd_secret`.
//!
//! This module provides the [`Vault`] struct, which uses the Linux-specific
//! `memfd_secret` system call to create a memory region that is invisible to
//! the kernel's page tables and most other processes, providing a secure
//! location for sensitive cryptographic material.

use crate::crypto::secret_box::SecretBox;
use memmap2::MmapMut;
use std::fs::File;
use std::io::{Error as IoError, Result as IoResult};
use std::os::unix::io::{FromRawFd, RawFd};
use zeroize::Zeroize;

/// The system call number for `memfd_secret` on x86_64.
#[cfg(target_arch = "x86_64")]
const SYS_MEMFD_SECRET: i64 = 447;

/// A secure container for sensitive data backed by `memfd_secret`.
///
/// `Vault` uses a secret memory file descriptor that is not visible in the
/// filesystem and whose memory is unmapped from the kernel page tables.
/// The memory is automatically zeroed when the `Vault` is dropped.
#[derive(Debug)]
pub struct Vault {
    mmap: MmapMut,
    #[cfg(test)]
    file: File,
}

#[cfg(test)]
impl std::os::unix::io::AsRawFd for Vault {
    fn as_raw_fd(&self) -> RawFd {
        std::os::unix::io::AsRawFd::as_raw_fd(&self.file)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.mmap[..].zeroize();
    }
}

impl Vault {
    /// Creates a new `Vault` containing the provided data.
    ///
    /// The provided `data` is copied into the vault. The source `SecretBox` is
    /// dropped at the end, ensuring the original sensitive data is zeroized
    /// from memory.
    ///
    /// # Errors
    ///
    /// Returns an error if the `memfd_secret` syscall fails or if the memory
    /// cannot be mapped.
    pub fn new(data: SecretBox) -> IoResult<Self> {
        let mut vault = Self::new_empty(data.as_slice().len())?;
        vault.mmap.copy_from_slice(data.as_slice());
        Ok(vault)
    }

    /// Creates a new empty `Vault` of the specified size.
    pub fn new_empty(len: usize) -> IoResult<Self> {
        // Create the secret memory file descriptor.
        // O_CLOEXEC ensures the FD is closed on exec.
        let fd = unsafe { libc::syscall(SYS_MEMFD_SECRET, libc::O_CLOEXEC as libc::c_long) };

        if fd < 0 {
            return Err(IoError::last_os_error());
        }
        let fd = fd as RawFd;

        // Wrap the raw FD in a File object to manage its lifetime.
        let file = unsafe { File::from_raw_fd(fd) };

        // Set the size of the secret memory region.
        file.set_len(len as u64)?;

        // Map the secret memory region into the process's address space.
        let mmap = unsafe { MmapMut::map_mut(&file)? };

        Ok(Vault {
            mmap,
            #[cfg(test)]
            file,
        })
    }

    /// Conceptually unsafe wrapper executing a closure with mutable access to the secure region.
    /// Allows zero-copy initialization.
    ///
    /// # Safety
    ///
    /// The caller must ensure that any raw pointers or FFI calls writing into the mutable slice
    /// do not write out of bounds. The slice length is guaranteed to be exactly the initialized size.
    pub unsafe fn write_secret<F, T>(&mut self, f: F) -> T
    where
        F: FnOnce(&mut [u8]) -> T,
    {
        f(&mut self.mmap[..])
    }

    /// Executes a closure with a temporary view of the secret key material.
    /// The secret key material is not copied and remains inside the secure region.
    pub fn with_secret<F, T>(&self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        f(&self.mmap[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    #[test]
    fn test_vault_creation_and_retrieval() {
        let data = *b"sensitive information";
        let original_data = data;
        let secret = SecretBox::new(data.to_vec());
        let vault = Vault::new(secret).expect("Failed to create vault");
        vault.with_secret(|secret_bytes| {
            assert_eq!(secret_bytes, &original_data);
        });
    }

    #[test]
    fn test_vault_with_empty_data() {
        let secret = SecretBox::new(vec![]);
        let vault = Vault::new(secret).expect("Failed to create empty vault");
        vault.with_secret(|secret_bytes| {
            assert!(secret_bytes.is_empty());
        });
    }

    #[test]
    fn test_multiple_vaults() {
        let s1 = *b"secret1";
        let v1 = Vault::new(SecretBox::new(s1.to_vec())).unwrap();
        let s2 = *b"secret2";
        let v2 = Vault::new(SecretBox::new(s2.to_vec())).unwrap();
        v1.with_secret(|s1_bytes| {
            v2.with_secret(|s2_bytes| {
                assert_ne!(s1_bytes, s2_bytes);
                assert_eq!(s1_bytes, b"secret1");
                assert_eq!(s2_bytes, b"secret2");
            });
        });
    }

    #[test]
    fn test_large_vault() {
        let data = vec![0u8; 1024 * 1024]; // 1MB
        let len = data.len();
        let vault = Vault::new(SecretBox::new(data)).expect("Failed to create large vault");
        vault.with_secret(|secret_bytes| {
            assert_eq!(secret_bytes.len(), len);
        });
    }

    #[test]
    fn test_memfd_backing_verification() {
        let data = *b"verification data";
        let vault = Vault::new(SecretBox::new(data.to_vec())).unwrap();
        let fd = vault.as_raw_fd();

        // 1. Verify filesystem magic number using fstatfs
        let mut statfs: libc::statfs = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstatfs(fd, &mut statfs) };
        assert_eq!(ret, 0, "fstatfs failed");

        // SECRETMEM_MAGIC is 0x5345434d ("SECM")
        const SECRETMEM_MAGIC: libc::c_long = 0x5345434d;
        assert_eq!(
            statfs.f_type, SECRETMEM_MAGIC,
            "Filesystem is not memfd_secret. Expected magic {:x}, got {:x}",
            SECRETMEM_MAGIC, statfs.f_type
        );

        // 2. Verify mapping in /proc/self/maps
        let ptr = vault.mmap.as_ptr() as usize;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::fstat(fd, &mut stat) };
        assert_eq!(ret, 0, "fstat failed");
        let expected_inode = stat.st_ino;

        let maps =
            std::fs::read_to_string("/proc/self/maps").expect("Failed to read /proc/self/maps");
        let found = maps.lines().any(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                return false;
            }

            let range: Vec<&str> = parts[0].split('-').collect();
            let start = usize::from_str_radix(range[0], 16).unwrap();
            let end = usize::from_str_radix(range[1], 16).unwrap();

            if ptr >= start && ptr < end {
                let inode = parts[4].parse::<u64>().unwrap_or(0);
                return inode == expected_inode && line.contains("/secretmem");
            }
            false
        });

        assert!(
            found,
            "Could not verify memfd_secret mapping in /proc/self/maps"
        );
    }

    #[test]
    fn test_zeroize_on_drop() {
        let data = *b"secret to be zeroed";
        let original_data = data;
        let vault = Vault::new(SecretBox::new(data.to_vec())).unwrap();

        // Create a second mapping of the same memory to spy on it
        // This is possible because we have access to the underlying File in tests
        let spy = unsafe { MmapMut::map_mut(&vault.file).expect("Failed to create spy mapping") };

        // Verify spy sees the data
        assert_eq!(&spy[..], &original_data);

        // Drop the vault, which should trigger zeroize
        drop(vault);

        // Verify the memory was zeroed
        assert!(
            spy.iter().all(|&b| b == 0),
            "Memory was not zeroed after drop"
        );
    }

    #[test]
    fn test_vault_empty_write_retrieval() {
        let mut vault = Vault::new_empty(32).expect("Failed to create empty vault");
        let data = *b"0123456789abcdef0123456789abcdef";

        unsafe {
            vault.write_secret(|vault_mut_slice| {
                vault_mut_slice.copy_from_slice(&data);
            });
        }

        vault.with_secret(|secret_bytes| {
            assert_eq!(secret_bytes, &data);
        });
    }
}
