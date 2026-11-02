//! virtsec eBPF kernel programs.
//!
//! Three hooks, each filling one fixed-size [`Event`] into the `EVENTS` ring
//! buffer:
//! * `execve`     , `sched:sched_process_exec` (executed binary, successful
//!   execs only).
//! * `connect`    , kprobes on `tcp_v4_connect` / `tcp_v6_connect` (dest ip:port).
//! * `file_write` , kprobe on `do_sys_openat2` (every open, openat, openat2 and
//!   creat), filtered in-kernel to *write* opens under sensitive paths, so
//!   userspace never sees the firehose.
//!
//! On ring-buffer backpressure we bump `DROPS` and return cleanly, never block,
//! never panic on event data.

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kprobe, map, tracepoint},
    maps::{Array, RingBuf},
    programs::{ProbeContext, TracePointContext},
    EbpfContext,
};
use virtsec_probe_common::{af, kind, Event, FILENAME_LEN};

/// Ring buffer carrying events to userspace (256 KiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Single-slot counter of events dropped because the ring buffer was full.
#[map]
static DROPS: Array<u64> = Array::with_max_entries(1, 0);

/// Sensitive path prefixes matched in-kernel for `file_write`.
/// `/etc/` covers `/etc/pve` (cluster config) on a node.
const SENSITIVE_PREFIXES: [&[u8]; 5] =
    [b"/etc/", b"/usr/bin/", b"/usr/sbin/", b"/root/", b"/boot/"];

// ---------------------------------------------------------------------------
// execve
// ---------------------------------------------------------------------------

/// Tracepoint: `sched:sched_process_exec`, in the new image after a successful
/// exec. Not `syscalls:sys_enter_execve`: on recent kernels (7.0) its BPF
/// programs miss most execs, and it also fires for failed PATH lookups.
#[tracepoint]
pub fn virtsec_execve(ctx: TracePointContext) -> u32 {
    let _ = try_execve(&ctx);
    0
}

fn try_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();

    // SAFETY: `e` is a freshly reserved, exclusively-owned slot sized for `Event`;
    // every field is initialized before `submit`.
    unsafe {
        fill_common(e, kind::EXEC);
        // `__data_loc char[] filename` at offset 8: the string's offset in the
        // record (low 16 bits), its length (high 16).
        if let Ok(loc) = ctx.read_at::<u32>(8) {
            let src = (ctx.as_ptr() as *const u8).add((loc & 0xffff) as usize);
            let _ = bpf_probe_read_kernel_str_bytes(src, &mut (*e).filename);
        }
    }

    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// file_write (openat with write intent, under a sensitive path)
// ---------------------------------------------------------------------------

/// kprobe: `do_sys_openat2(int dfd, const char __user *filename, struct
/// open_how *how)`, where every open syscall ends up. Not the
/// `syscalls:sys_enter_openat` tracepoint: on recent kernels (7.0) its BPF
/// programs miss most calls, and `open` / `creat` never pass there. Emits only
/// write-opens under a sensitive path; everything else is filtered here.
#[kprobe]
pub fn virtsec_openat(ctx: ProbeContext) -> u32 {
    let _ = try_openat(&ctx);
    0
}

fn try_openat(ctx: &ProbeContext) -> Result<(), i64> {
    let filename_ptr: *const u8 = ctx.arg(1).ok_or(0i64)?;
    let how: *const u64 = ctx.arg(2).ok_or(0i64)?;
    if filename_ptr.is_null() || how.is_null() {
        return Ok(());
    }
    // `struct open_how` starts with `u64 flags`.
    let flags: u64 = unsafe { bpf_probe_read_kernel(how) }.unwrap_or(0);
    if !is_write_open(flags) {
        return Ok(());
    }

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();

    // SAFETY: as in `try_execve`. We read the path into the slot, then keep the
    // event only if it targets a sensitive prefix, else discard it.
    unsafe {
        fill_common(e, kind::FILE_WRITE);
        let read = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*e).filename);
        let sensitive = match read {
            Ok(bytes) => is_sensitive(bytes),
            Err(_) => false,
        };
        if !sensitive {
            entry.discard(0);
            return Ok(());
        }
    }

    entry.submit(0);
    Ok(())
}

fn is_write_open(flags: u64) -> bool {
    // Access mode is the low 2 bits: 1=O_WRONLY, 2=O_RDWR. Plus create/trunc/append.
    let acc = flags & 0o3;
    acc == 1 || acc == 2 || (flags & (0o100 | 0o1000 | 0o2000)) != 0
}

fn is_sensitive(path: &[u8]) -> bool {
    let mut p = 0;
    while p < SENSITIVE_PREFIXES.len() {
        if starts_with(path, SENSITIVE_PREFIXES[p]) {
            return true;
        }
        p += 1;
    }
    false
}

#[inline(always)]
fn starts_with(path: &[u8], prefix: &[u8]) -> bool {
    let mut i = 0;
    // Hard cap keeps the verifier happy; all prefixes are far shorter than 32.
    while i < prefix.len() && i < 32 {
        if i >= path.len() || path[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

// ---------------------------------------------------------------------------
// connect (TCP v4/v6)
// ---------------------------------------------------------------------------

/// kprobe: `tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int len)`.
#[kprobe]
pub fn virtsec_tcp_v4_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx, af::INET);
    0
}

/// kprobe: `tcp_v6_connect(struct sock *sk, struct sockaddr *uaddr, int len)`.
#[kprobe]
pub fn virtsec_tcp_v6_connect(ctx: ProbeContext) -> u32 {
    let _ = try_connect(&ctx, af::INET6);
    0
}

fn try_connect(ctx: &ProbeContext, family: u16) -> Result<(), i64> {
    // arg1 = struct sockaddr *uaddr (kernel memory at this point).
    let uaddr: *const u8 = ctx.arg(1).ok_or(1i64)?;
    if uaddr.is_null() {
        return Ok(());
    }

    // sockaddr_in{,6}: sin_port at offset 2 (big-endian). Address at offset 4
    // (v4) / offset 8 (v6).
    let port_be: u16 = unsafe { bpf_probe_read_kernel((uaddr as usize + 2) as *const u16) }?;
    let dport = u16::from_be(port_be);

    let mut daddr = [0u8; 16];
    match family {
        af::INET => {
            let a: [u8; 4] =
                unsafe { bpf_probe_read_kernel((uaddr as usize + 4) as *const [u8; 4]) }?;
            daddr[..4].copy_from_slice(&a);
        }
        _ => {
            let a: [u8; 16] =
                unsafe { bpf_probe_read_kernel((uaddr as usize + 8) as *const [u8; 16]) }?;
            daddr = a;
        }
    }

    let Some(mut entry) = EVENTS.reserve::<Event>(0) else {
        bump_drops();
        return Err(0);
    };
    let e = entry.as_mut_ptr();
    // SAFETY: as above.
    unsafe {
        fill_common(e, kind::CONNECT);
        (*e).daddr = daddr;
        (*e).dport = dport;
        (*e).af = family;
    }
    entry.submit(0);
    Ok(())
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

/// Fill the fields common to every event and zero the rest.
///
/// SAFETY: `e` must point at a valid, writable `Event` slot.
unsafe fn fill_common(e: *mut Event, kind: u32) {
    (*e).kind = kind;
    (*e).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*e).uid = bpf_get_current_uid_gid() as u32;
    (*e).cgroup_id = bpf_get_current_cgroup_id();
    (*e)._pad = 0;
    (*e).daddr = [0u8; 16];
    (*e).dport = 0;
    (*e).af = 0;
    match bpf_get_current_comm() {
        Ok(comm) => (*e).comm = comm,
        Err(_) => (*e).comm = [0u8; 16],
    }
    core::ptr::write_bytes((*e).filename.as_mut_ptr(), 0, FILENAME_LEN);
}

fn bump_drops() {
    if let Some(ptr) = DROPS.get_ptr_mut(0) {
        // SAFETY: single-slot counter; a lost increment is acceptable.
        unsafe { *ptr += 1 };
    }
}

/// GPL license, required for the tracepoint/kprobe + `bpf_probe_read` helpers.
#[no_mangle]
#[link_section = "license"]
static LICENSE: [u8; 4] = *b"GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable in verified BPF; present to satisfy the compiler.
    loop {}
}
