// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Matthew Jackson

//! A twelve-line executor, so the probe can drive oauth-as's async API without linking tokio.
//!
//! This matters to the measurement rather than to convenience: tokio is tens of kilobytes of
//! runtime, scheduler and reactor, and none of it is oauth-as's cost. Only the `axum` feature
//! pulls tokio in (a host needs something to bind a listener with), and only that row of the
//! report should be charged for it.
//!
//! Busy-polls rather than parking. Every future the probe drives is backed by `MemoryStorage`, so
//! it is ready on the first poll; a real host's storage is not, but what its executor costs is
//! the host's number and not this crate's.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

const VTABLE: RawWakerVTable = RawWakerVTable::new(
    |_| RawWaker::new(std::ptr::null(), &VTABLE),
    |_| {},
    |_| {},
    |_| {},
);

pub fn block_on<F: Future>(future: F) -> F::Output {
    // SAFETY: the vtable's clone returns an equivalent no-op waker and wake/drop do nothing, so
    // every contract on RawWaker is satisfied trivially.
    let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
        std::hint::spin_loop();
    }
}
