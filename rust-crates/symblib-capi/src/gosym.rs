// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{FfiResult, StatusCode, SymblibPointResolver};
use std::ffi::{c_char, CStr};
use std::path::Path;
use symblib::symbconv::PointResolver;
use symblib::{gosym::GoRuntimeInfo, objfile};

pub struct SymblibGoRuntime {
    #[allow(dead_code)]
    runtime: GoRuntimeInfo<'static>,
}

#[no_mangle]
pub unsafe extern "C" fn symblib_goruntime_new(
    executable: *const c_char,
    runtime: *mut *mut SymblibPointResolver,
) -> StatusCode {
    match goruntime_new_impl(executable, runtime) {
        Ok(()) => StatusCode::Ok,
        Err(e) => e,
    }
}

unsafe fn goruntime_new_impl(
    executable: *const c_char,
    runtime: *mut *mut SymblibPointResolver,
) -> FfiResult {
    let executable = CStr::from_ptr(executable)
        .to_str()
        .map(Path::new)
        .map_err(|_| StatusCode::BadUtf8)?;

    let obj = Box::leak(Box::new(objfile::File::load(executable)?));
    let obj_reader = obj.parse()?;
    let go_runtime = GoRuntimeInfo::open(&obj_reader)?;

    let point_resolver = Box::new(SymblibPointResolver::new(
        Box::new(go_runtime) as Box<dyn PointResolver + Send>
    ));
    *runtime = Box::into_raw(point_resolver);
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn symblib_goruntime_free(runtime: *mut SymblibPointResolver) {
    if !runtime.is_null() {
        drop(Box::from_raw(runtime));
    }
}
