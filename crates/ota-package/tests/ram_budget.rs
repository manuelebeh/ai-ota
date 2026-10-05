//! Asserts the in-memory parser's peak allocation while parsing the richest golden
//! fixture (`full.otapkg`) stays within the 16 KiB RAM budget from ADR 0001.
//!
//! This measures the *reference* in-memory parser in this crate, not the `no_std`
//! streaming parser a real device would run (that one lives in firmware and is out of
//! scope for this crate) — but since the golden fixtures are all under 4 KiB, a failure
//! here would still mean something has gone badly wrong (e.g. an accidental O(n^2) copy
//! or an unbounded buffer), so it's a useful regression guard even though it isn't a
//! substitute for an on-device measurement.
//!
//! A custom global allocator is required to measure peak bytes; it must live in its own
//! test binary so it doesn't affect other tests in the same process.

use std::alloc::{GlobalAlloc, Layout, System};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountingAllocator;

static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::SeqCst) + layout.size();
            PEAK.fetch_max(now, Ordering::SeqCst);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        CURRENT.fetch_sub(layout.size(), Ordering::SeqCst);
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

const RAM_BUDGET_BYTES: usize = 16 * 1024;

#[test]
fn parse_full_fixture_stays_within_ram_budget() {
    let bytes = fs::read("tests/golden/v1/full.otapkg").expect("reading full.otapkg fixture");

    // Baseline out the test harness's own already-live allocations (argv, thread stacks,
    // the `bytes` buffer itself, etc.) — we want the budget to cover only what `parse`
    // itself allocates on top of that baseline, not the whole process's history.
    let baseline = CURRENT.load(Ordering::SeqCst);
    PEAK.store(baseline, Ordering::SeqCst);

    let parsed = ota_package::parse(&bytes).expect("parsing full.otapkg");
    let peak = PEAK.load(Ordering::SeqCst);

    // Keep `parsed` alive until after the peak is read, so its allocations count.
    std::hint::black_box(&parsed);

    let used = peak.saturating_sub(baseline);
    assert!(
        used <= RAM_BUDGET_BYTES,
        "parsing full.otapkg allocated {used} bytes above baseline, budget is {RAM_BUDGET_BYTES} bytes"
    );
}
