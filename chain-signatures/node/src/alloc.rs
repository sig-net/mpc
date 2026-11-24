//! Global memory allocator configuration, introspection, and verification.
//!
//! # Architecture & Rationale
//! Under multi-threaded Tokio runtimes, tasks frequently allocate buffers on one thread and
//! deallocate them on another during task-stealing and channel message passing. The standard
//! `glibc` allocator (`ptmalloc`) suffers from cross-thread arena lock contention and heap
//! fragmentation under this pattern. `jemalloc` resolves this by providing:
//! - Per-thread memory arenas and thread-local caching (`tcache`) that eliminate lock contention.
//! - Substantially higher message throughput and lower allocation latency in async workloads.
//!
//! # Container RSS Mitigation
//! By default, jemalloc retains dirty and muzzy pages for 10 seconds before purging them back
//! to the OS, which can leave high residual RSS in memory-constrained containers after traffic bursts.
//! To prevent this, jemalloc is configured at build time via `JEMALLOC_SYS_WITH_MALLOC_CONF` in
//! `.cargo/config.toml` and `Dockerfile` with a 1-second decay time (`--with-malloc-conf`):
//! ```text
//! dirty_decay_ms:1000,muzzy_decay_ms:1000
//! ```
//! Operators can override this at runtime via the `_RJEM_MALLOC_CONF` environment variable:
//! ```bash
//! export _RJEM_MALLOC_CONF="dirty_decay_ms:2000,muzzy_decay_ms:2000"
//! ```
//!
//! # Fallback to System Allocator (Debuggers & ASan)
//! When running under memory sanitizers or debuggers (e.g. AddressSanitizer `ASan`, Valgrind),
//! compile with `--no-default-features` to use the system allocator:
//! ```bash
//! cargo run -p mpc-node --no-default-features
//! ```

#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
))]
pub use tikv_jemallocator::Jemalloc;

#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
))]
extern "C" {
    #[link_name = "_rjem_mallctl"]
    fn mallctl(
        name: *const libc::c_char,
        oldp: *mut libc::c_void,
        oldlenp: *mut libc::size_t,
        newp: *mut libc::c_void,
        newlen: libc::size_t,
    ) -> libc::c_int;
}

/// Query active jemalloc dirty and muzzy decay times in milliseconds.
#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
))]
pub fn query_decay_ms() -> anyhow::Result<(i64, i64)> {
    let mut dirty: libc::ssize_t = -1;
    let mut dirty_len = std::mem::size_of::<libc::ssize_t>();
    let mut muzzy: libc::ssize_t = -1;
    let mut muzzy_len = std::mem::size_of::<libc::ssize_t>();

    let ret_dirty = unsafe {
        mallctl(
            c"opt.dirty_decay_ms".as_ptr(),
            &mut dirty as *mut _ as *mut libc::c_void,
            &mut dirty_len,
            std::ptr::null_mut(),
            0,
        )
    };
    anyhow::ensure!(
        ret_dirty == 0,
        "mallctl(opt.dirty_decay_ms) failed with error code {ret_dirty}"
    );

    let ret_muzzy = unsafe {
        mallctl(
            c"opt.muzzy_decay_ms".as_ptr(),
            &mut muzzy as *mut _ as *mut libc::c_void,
            &mut muzzy_len,
            std::ptr::null_mut(),
            0,
        )
    };
    anyhow::ensure!(
        ret_muzzy == 0,
        "mallctl(opt.muzzy_decay_ms) failed with error code {ret_muzzy}"
    );

    Ok((dirty as i64, muzzy as i64))
}

/// Verify that jemalloc is properly configured with 1000ms decay time (unless overridden by operator).
#[cfg(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
))]
pub fn verify_configuration() -> anyhow::Result<()> {
    let (dirty, muzzy) = query_decay_ms()?;
    #[allow(clippy::disallowed_methods)]
    let has_override = std::env::var_os("_RJEM_MALLOC_CONF").is_some();
    if !has_override && (dirty != 1000 || muzzy != 1000) {
        anyhow::bail!(
            "jemalloc decay settings unconfigured: dirty_decay_ms={dirty}, muzzy_decay_ms={muzzy} \
             (expected 1000ms via JEMALLOC_SYS_WITH_MALLOC_CONF build env or _RJEM_MALLOC_CONF runtime env)"
        );
    }
    Ok(())
}

/// No-op verification when jemalloc is disabled or on unsupported targets.
#[cfg(not(all(
    feature = "jemalloc",
    not(target_env = "msvc"),
    not(target_arch = "wasm32")
)))]
pub fn verify_configuration() -> anyhow::Result<()> {
    Ok(())
}
