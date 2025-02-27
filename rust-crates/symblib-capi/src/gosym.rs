// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{FfiResult, StatusCode, SymblibString};
use fallible_iterator::FallibleIterator;
use std::ffi::{c_char, CStr};
use std::path::Path;
use symblib::{gosym::GoRuntimeInfo, objfile, VirtAddr};

pub struct SymblibGoRuntime {
    // Keep a reference to the backing executable
    _obj: &'static objfile::File,
    runtime: GoRuntimeInfo<'static>,
}

#[derive(Debug)]
#[repr(C)]
pub struct SymblibGoFunc {
    start_addr: u64,
    function_name: SymblibString,
    file_name: SymblibString,
    line_number: u32,
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
        _obj: obj,
    });
    *runtime = Box::into_raw(runtime_handle);
    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn symblib_goruntime_lookup(
    runtime: *mut SymblibGoRuntime,
    addr: u64,
    func_info: *mut *mut SymblibGoFunc,
) -> StatusCode {
    let runtime = &*runtime;
    match runtime.runtime.find_func(VirtAddr::from(addr)) {
        Ok(Some(func)) => {
            let name = match func.name() {
                Ok(n) => n,
                Err(_) => return StatusCode::GosymMissingFuncName,
            };

            let mut file_name = "";
            let mut line_number = 0;

            // For file mapping
            let mut file_iter = match func.file_mapping() {
                Ok(iter) => iter,
                Err(_) => return StatusCode::GosymBadFileMapping,
            };
            while let Ok(Some((range, file))) = file_iter.next() {
                if range.contains(&VirtAddr::from(addr)) {
                    file_name = file.unwrap_or("unknown");
                    break;
                }
            }

            // For line mapping
            let mut line_iter = match func.line_mapping() {
                Ok(iter) => iter,
                Err(_) => return StatusCode::GosymBadLineMapping,
            };
            while let Ok(Some((range, line))) = line_iter.next() {
                if range.contains(&VirtAddr::from(addr)) {
                    line_number = line.unwrap_or(0);
                    break;
                }
            }

            let info = Box::new(SymblibGoFunc {
                start_addr: func.start_addr(),
                function_name: name.to_string().into(),
                file_name: file_name.to_string().into(),
                line_number: line_number,
            });

            *func_info = Box::into_raw(info);
            StatusCode::Ok
        }
        Ok(None) => StatusCode::GosymMissingAddrMapping,
        Err(_) => StatusCode::GosymBadAddrLookup,
    }
}

#[no_mangle]
pub unsafe extern "C" fn symblib_goruntime_free(runtime: *mut SymblibGoRuntime) {
    if !runtime.is_null() {
        drop(Box::from_raw(runtime));
    }
}
