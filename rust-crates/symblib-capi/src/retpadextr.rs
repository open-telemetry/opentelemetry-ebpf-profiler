// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Expose return pad generation to C.
//!
//! This currently uses a background thread to do the processing because that
//! is the easiest way to bridge the push-based range extraction API with
//! the pull-based iterator API consumed by the return pad generation code.
//! It may simplify things in the future if we were to rework the return pad
//! generation code to be push-based as well.

use super::{SymblibSlice, SymblibString};
use crate::{FfiResult, StatusCode, SymblibRange};
use fallible_iterator::{FallibleIterator, IteratorExt as _};
use std::ffi::{c_char, c_void, CStr};
use std::path::Path;
use std::sync::mpsc::TrySendError;
use std::thread::JoinHandle;
use std::{sync::mpsc, thread};
use symblib::{objfile, retpads, symbfile, VirtAddr};

/// Create a new return pad extractor.
///
/// The instance must be freed via a call to [`symblib_retpadextr_free`].
#[no_mangle]
pub unsafe extern "C" fn symblib_retpadextr_new(
    executable: *const c_char,
    extr: *mut *mut SymblibRetPadExtractor, // out arg
) -> StatusCode {
    match retpadextr_new_impl(executable, extr) {
        Ok(()) => StatusCode::Ok,
        Err(e) => e,
    }
}

unsafe fn retpadextr_new_impl(
    executable: *const c_char,
    extr: *mut *mut SymblibRetPadExtractor, // out arg
) -> FfiResult {
    assert!(!executable.is_null());
    let executable = CStr::from_ptr(executable)
        .to_str()
        .map(Path::new)
        .map_err(|_| StatusCode::BadUtf8)?;

    // Open and mmap main object file.
    let obj = objfile::File::load(Path::new(executable))?;
    let (range_tx, range_rx) = mpsc::sync_channel(128);
    let (ret_pad_tx, ret_pad_rx) = mpsc::sync_channel(128);

    let thread_handle = Some(thread::spawn(move || {
        extractor_thread(obj, range_rx, ret_pad_tx)
    }));

    *extr = Box::into_raw(Box::new(SymblibRetPadExtractor {
        thread_handle,
        ret_pad_rx,
        range_tx: Some(range_tx),
    }));

    Ok(())
}

fn extractor_thread(
    obj: objfile::File,
    range_rx: mpsc::Receiver<symbfile::Range>,
    ret_pad_tx: mpsc::SyncSender<SymblibReturnPad>,
) -> FfiResult {
    let obj_reader = obj.parse()?;

    let range_iter = range_rx
        .into_iter()
        .into_fallible()
        .map_err(|_| -> retpads::Error { unreachable!("source iterator is infallible") });

    retpads::extract_retpads(&obj_reader, range_iter, |ret_pad| {
        ret_pad_tx
            .send(SymblibReturnPad::from(ret_pad))
            .map_err(|_| retpads::Error::Other(std::io::Error::other("TODO").into()))
    })?;

    Ok(())
}

/// Visitor callback for symbol events.
///
/// The return pad is **borrowed** to the callee and the pointer is only valid
/// for the duration of the visitor call. Returning an error will abort further
/// execution and return early.
pub type RetPadVisitor =
    unsafe extern "C" fn(user_data: *mut c_void, ret_pad: *const SymblibReturnPad) -> StatusCode;

/// Submit a new range to the return pad extractor.
///
/// The callback may be invoked 0..n times for each range submitted. Processing
/// is happening asynchronously in the background: there is no guarantee that
/// the return pads passed to the visitor at each call correspond to the range
/// that was just submitted.
///
/// The user_data pointer is passed to the visitor untouched and may be `NULL`.
///
/// Once all ranges have been submitted, call this function with a `NULL` range
/// once to indicate this to force all remaining buffered return pads to be
/// flushed.
#[no_mangle]
pub unsafe extern "C" fn symblib_retpadextr_submit(
    extr: *mut SymblibRetPadExtractor,
    range: *const SymblibRange,
    visitor: RetPadVisitor,
    user_data: *mut c_void,
) -> StatusCode {
    match retpadextr_submit_impl(extr, range, visitor, user_data) {
        Ok(()) => StatusCode::Ok,
        Err(e) => e,
    }
}

unsafe fn retpadextr_submit_impl(
    extr: *mut SymblibRetPadExtractor,
    range: *const SymblibRange,
    visitor: RetPadVisitor,
    user_data: *mut c_void,
) -> FfiResult {
    assert!(!extr.is_null());
    let extr: &mut SymblibRetPadExtractor = &mut *extr;

    // Wrap visitor to make it rustier.
    let visitor = |rng: SymblibReturnPad| -> FfiResult {
        FfiResult::from(unsafe { visitor(user_data, &rng) })
    };

    // Communicate with the worker.
    if range.is_null() {
        // Null range indicates end of ranges: drop our range TX to notify the
        // worker thread that we're done here.
        drop(extr.range_tx.take());

        // Blockingly read back results until the thread drops the channel.
        extr.ret_pad_rx.iter().try_for_each(visitor)?;

        // Wait for thread to exit and retrieve the result.
        extr.thread_handle
            .take()
            .map(|x| x.join().unwrap(/* forward panic */))
            .transpose()?;
    } else {
        let Some(range_tx) = &extr.range_tx else {
            return Err(StatusCode::AlreadyClosed);
        };

        let mut range = symbfile::Range::clone(&(*range).rust_range);
        while let Err(e) = range_tx.try_send(range) {
            match e {
                TrySendError::Disconnected(_) => {
                    // TODO: can this even happen?
                    return Err(StatusCode::AlreadyClosed);
                }
                TrySendError::Full(returned) => {
                    // TX channel is clogged. Read back items from the output
                    // channel until the worker made progress.
                    extr.ret_pad_rx.try_iter().try_for_each(visitor)?;
                    std::thread::yield_now();
                    range = returned;
                }
            }
        }

        // Read as much as we can without blocking.
        extr.ret_pad_rx.try_iter().try_for_each(visitor)?;
    }

    Ok(())
}

/// Frees a return pad extractor.
#[no_mangle]
pub unsafe extern "C" fn symblib_retpadextr_free(extr: *mut SymblibRetPadExtractor) {
    let extr = Box::from_raw(extr);
    if let Some((handle, rx)) = extr.thread_handle.zip(extr.range_tx) {
        drop(rx);
        handle.join().unwrap(/* forward panic */).ok();
    }
}

/// Handle to a return pad extractor background thread.
///
/// Opaque to C.
#[repr(C)]
pub struct SymblibRetPadExtractor {
    thread_handle: Option<JoinHandle<FfiResult>>,
    range_tx: Option<mpsc::SyncSender<symbfile::Range>>,
    ret_pad_rx: mpsc::Receiver<SymblibReturnPad>,
}

/// FFI-safe variant of [`symbfile::ReturnPad`].
#[repr(C)]
#[derive(Debug)]
pub struct SymblibReturnPad {
    pub elf_va: VirtAddr,
    pub entries: SymblibSlice<SymblibReturnPadEntry>,
}

impl From<symbfile::ReturnPad> for SymblibReturnPad {
    fn from(pad: symbfile::ReturnPad) -> Self {
        let entries: Vec<SymblibReturnPadEntry> = pad.entries.into_iter().map(Into::into).collect();

        Self {
            elf_va: pad.elf_va,
            entries: entries.into(),
        }
    }
}

/// FFI-safe variant of [`symbfile::ReturnPadEntry`].
#[repr(C)]
#[derive(Debug)]
pub struct SymblibReturnPadEntry {
    pub func: SymblibString, // never null
    pub file: SymblibString, // may be null
    pub line: u32,           // 0 = unknown
}

impl From<symbfile::ReturnPadEntry> for SymblibReturnPadEntry {
    fn from(entry: symbfile::ReturnPadEntry) -> Self {
        Self {
            func: entry.func.into(),
            file: entry.file.into(),
            line: entry.line.unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use std::ptr;

    extern "C" fn retpad_visitor(
        user_data: *mut c_void,
        rng: *const SymblibReturnPad,
    ) -> StatusCode {
        assert!(user_data.is_null());
        assert!(!rng.is_null());
        dbg!(unsafe { &*rng });
        StatusCode::Ok
    }

    unsafe extern "C" fn rng_visitor(
        user_data: *mut c_void,
        rng: *const SymblibRange,
    ) -> StatusCode {
        let extr = user_data as *mut SymblibRetPadExtractor;
        symblib_retpadextr_submit(extr, rng, retpad_visitor, ptr::null_mut())
    }

    #[test]
    fn rng_retpad_extr_integration() {
        let file = c"../symblib/testdata/inline";

        let mut extr = ptr::null_mut();
        let mut status = unsafe { symblib_retpadextr_new(file.as_ptr(), &mut extr) };
        assert_eq!(status, StatusCode::Ok);

        status = unsafe { symblib_rangeextr(file.as_ptr(), false, rng_visitor, extr as _) };
        assert_eq!(status, StatusCode::Ok);

        let status = unsafe {
            symblib_retpadextr_submit(extr, ptr::null(), retpad_visitor, ptr::null_mut())
        };
        assert_eq!(status, StatusCode::Ok);

        unsafe {
            assert!((*extr).thread_handle.is_none());
            assert!((*extr).range_tx.is_none());
            assert_eq!((*extr).ret_pad_rx.iter().count(), 0);

            symblib_retpadextr_free(extr)
        }
    }
}
