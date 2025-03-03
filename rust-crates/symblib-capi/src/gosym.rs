// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{FfiResult, StatusCode};
use std::ffi::{c_char, CStr};
use std::path::Path;
use symblib::{gosym::GoRuntimeInfo, objfile};

pub struct SymblibGoRuntime {
    runtime: GoRuntimeInfo<'static>,
}

#[no_mangle]
pub unsafe extern "C" fn symblib_goruntime_new(
    executable: *const c_char,
    runtime: *mut *mut SymblibGoRuntime,
) -> StatusCode {
    match goruntime_new_impl(executable, runtime) {
        Ok(()) => StatusCode::Ok,
        Err(e) => e,
    }
}

unsafe fn goruntime_new_impl(
    executable: *const c_char,
    runtime: *mut *mut SymblibGoRuntime,
) -> FfiResult {
    let executable = CStr::from_ptr(executable)
        .to_str()
        .map(Path::new)
        .map_err(|_| StatusCode::BadUtf8)?;

    let obj = Box::leak(Box::new(objfile::File::load(executable)?));
    let obj_reader = obj.parse()?;
    let go_runtime = GoRuntimeInfo::open(&obj_reader)?;

    let runtime_handle = Box::new(SymblibGoRuntime {
        runtime: go_runtime,
    });
    *runtime = Box::into_raw(runtime_handle);
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn symblib_goruntime_free(runtime: *mut SymblibGoRuntime) {
    if !runtime.is_null() {
        drop(Box::from_raw(runtime));
    }
}