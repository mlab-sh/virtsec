//! Wire types shared between the eBPF programs (kernel) and the userspace loader.
//!
//! `no_std` so the exact same `#[repr(C)]` layout compiles for the BPF target
//! and for the host. One fixed-size [`Event`] flows over the ring buffer; the
//! `kind` discriminant says which fields are meaningful.

#![no_std]

/// Length of the `comm` (thread name) field, matching the kernel's `TASK_COMM_LEN`.
pub const COMM_LEN: usize = 16;
/// Max captured path/binary length (truncated beyond this).
pub const FILENAME_LEN: usize = 256;

/// Event kind discriminants. These map 1:1 to event kind strings in
/// userspace (`exec`, `connect`, `file_write`).
pub mod kind {
    pub const EXEC: u32 = 0;
    pub const CONNECT: u32 = 1;
    pub const FILE_WRITE: u32 = 2;
}

/// Address family values (as in `<sys/socket.h>`), for `Event::af`.
pub mod af {
    pub const INET: u16 = 2;
    pub const INET6: u16 = 10;
}

/// A single kernel event. Fixed size for simple, fast ring-buffer transport.
///
/// Field relevance by `kind`:
/// * `exec`: `comm`, `filename` (the executed binary), pid/uid/cgroup.
/// * `connect`: `daddr`, `dport`, `af`, pid/uid/cgroup.
/// * `file_write`: `filename` (the opened path), pid/uid/cgroup.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    /// One of [`kind`].
    pub kind: u32,
    pub pid: u32,
    pub uid: u32,
    pub _pad: u32,
    /// Kernel cgroup id (v2 inode) of the process, a stable per-container key.
    pub cgroup_id: u64,
    /// NUL-padded thread name.
    pub comm: [u8; COMM_LEN],
    /// NUL-padded path (exec binary or written file).
    pub filename: [u8; FILENAME_LEN],
    /// Destination address (IPv4 in the first 4 bytes, or full IPv6).
    pub daddr: [u8; 16],
    /// Destination port, host byte order.
    pub dport: u16,
    /// Address family (see [`af`]).
    pub af: u16,
}

impl Event {
    /// An all-zero event (BPF side fills fields in place).
    pub const fn zeroed() -> Self {
        Self {
            kind: 0,
            pid: 0,
            uid: 0,
            _pad: 0,
            cgroup_id: 0,
            comm: [0; COMM_LEN],
            filename: [0; FILENAME_LEN],
            daddr: [0; 16],
            dport: 0,
            af: 0,
        }
    }

    /// Copy an `Event` out of a ring-buffer record (unaligned-safe).
    ///
    /// Returns `None` if the record is too short.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < core::mem::size_of::<Self>() {
            return None;
        }
        // SAFETY: length checked above; `Event` is `repr(C)` plain-old-data, and
        // `read_unaligned` tolerates any pointer alignment.
        Some(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }
}
