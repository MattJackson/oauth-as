// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A hand-rolled counting allocator for `tests/allocation.rs`. No new dependency: this wraps
//! [`std::alloc::System`] and counts calls and bytes in atomics.
//!
//! The counters are PROCESS WIDE (a `#[global_allocator]` has no way to be anything else), so a
//! measurement is only trustworthy if nothing unrelated allocates while it is being taken.
//! [`TEST_LOCK`] exists to serialize measuring code against itself, but note what it CANNOT do:
//! `std`'s test harness starts one OS thread per `#[test]` up front (up to the `--test-threads`
//! limit), and thread creation itself touches the allocator (stack bookkeeping, TLS) on platforms
//! where that is not a raw `mmap`. That noise happens outside any lock this crate can take, so
//! `tests/allocation.rs` settled on a single `#[test]` function for the whole binary: with only
//! one test to run, the harness has nothing else to schedule concurrently. [`TEST_LOCK`] is kept
//! anyway as defense in depth and as documentation of the requirement, in case a future edit adds
//! a second `#[test]` to that file.
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Serializes the bodies of the allocation-sensitive tests in this binary. `std`'s test harness
/// runs `#[test]` functions on separate threads by default, and the counters below are global to
/// the process, so two measuring tests running at once would corrupt each other's deltas. Holding
/// this lock for a whole test body turns "many tests, one process" back into "one test at a time".
pub static TEST_LOCK: Mutex<()> = Mutex::new(());

static ALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static DEALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);
static BYTES_ALLOCATED: AtomicUsize = AtomicUsize::new(0);

/// Counts every call that passes through it and delegates the actual memory work to `System`. The
/// counts are cumulative for the process's whole lifetime; callers read deltas via [`Snapshot`].
pub struct CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        BYTES_ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        BYTES_ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // A grow-in-place is still a request for different memory as far as the caller's cost is
        // concerned, so it counts as one allocation event of `new_size` bytes. This matches how
        // `Vec`/`String` growth actually costs a caller: one realloc, not an alloc plus a dealloc.
        ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
        BYTES_ALLOCATED.fetch_add(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

/// A point-in-time reading of the counters.
#[derive(Debug, Clone, Copy)]
pub struct Snapshot {
    alloc_calls: usize,
    dealloc_calls: usize,
    bytes_allocated: usize,
}

/// The change in the counters between two snapshots (or across a measured closure).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Delta {
    /// Number of `alloc`/`alloc_zeroed`/`realloc` calls observed.
    pub allocs: usize,
    /// Number of `dealloc` calls observed.
    pub deallocs: usize,
    /// Sum of requested bytes across the counted alloc-family calls.
    pub bytes: usize,
}

/// Read the counters now.
pub fn snapshot() -> Snapshot {
    Snapshot {
        alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
        dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
        bytes_allocated: BYTES_ALLOCATED.load(Ordering::Relaxed),
    }
}

impl Snapshot {
    /// The change from `self` (taken earlier) to `later`.
    pub fn delta_to(&self, later: Snapshot) -> Delta {
        Delta {
            allocs: later.alloc_calls.saturating_sub(self.alloc_calls),
            deallocs: later.dealloc_calls.saturating_sub(self.dealloc_calls),
            bytes: later.bytes_allocated.saturating_sub(self.bytes_allocated),
        }
    }
}

/// Run `f`, returning its result and the allocator activity observed strictly inside the call.
/// Keep `f` narrow: only the code under test should run inside it, since the counters cannot tell
/// this crate's allocations from anyone else's on the same thread.
pub fn measure<F, R>(f: F) -> (R, Delta)
where
    F: FnOnce() -> R,
{
    let before = snapshot();
    let result = f();
    let after = snapshot();
    (result, before.delta_to(after))
}
