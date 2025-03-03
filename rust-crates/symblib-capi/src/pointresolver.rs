use symblib::VirtAddr;
use symblib::symbconv;
use symblib::symbconv::PointResolver;
use crate::{StatusCode, SymblibString, SymblibSlice};
 use crate::SymblibGoRuntime;

use std::slice;

#[repr(C)]
#[derive(Debug)]
pub struct SymblibResolvedSymbol {
    pub start_addr: VirtAddr,
    pub function_name: SymblibString,    // may be null
    pub file_names: SymblibSlice<SymblibString>,
    pub line_numbers: SymblibSlice<u32>,
}

impl From<symbconv::ResolvedSymbol> for SymblibResolvedSymbol {
    fn from(sym: symbconv::ResolvedSymbol) -> Self {
        let file_names: Vec<SymblibString> = sym.file_names
            .unwrap_or_default()
            .into_iter()
            .map(Into::into)
            .collect();
            
        let line_numbers: Vec<u32> = sym.line_numbers
            .unwrap_or_default();

        Self {
            start_addr: sym.start_addr,
            function_name: sym.function_name.into(),
            file_names: file_names.into(),
            line_numbers: line_numbers.into(),
        }
    }
}

#[repr(C)]
pub struct SymblibPointResolver {
    inner: Box<dyn PointResolver + Send>,
}

#[no_mangle]
pub unsafe extern "C" fn symblib_point_resolver_symbols_for_pc(
    resolver: *const SymblibPointResolver,
    pc: VirtAddr,
    out_symbols: *mut *mut SymblibResolvedSymbol,
    out_len: *mut usize,
) -> StatusCode {
    if resolver.is_null() || out_symbols.is_null() || out_len.is_null() {
        return StatusCode::InvalArg;
    }

    let resolver = unsafe { &*resolver };
    
    match resolver.inner.symbols_for_pc(pc) {
        Ok(symbols) => {
            let symbols: Vec<SymblibResolvedSymbol> = symbols
                .into_iter()
                .map(Into::into)
                .collect();

            let boxed = symbols.into_boxed_slice();
            unsafe {
                *out_len = boxed.len();
                *out_symbols = Box::into_raw(boxed) as *mut SymblibResolvedSymbol;
            }
            
            StatusCode::Ok
        }
        Err(_) => StatusCode::PointResolver
    }
}

#[no_mangle]
pub unsafe extern "C" fn symblib_point_resolver_free_symbols(
    symbols: *mut SymblibResolvedSymbol,
    len: usize,
) {
    if !symbols.is_null() {
        unsafe {
            drop(Box::from_raw(slice::from_raw_parts_mut(symbols, len)));
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn symblib_go_runtime_as_point_resolver(
    runtime: *const SymblibGoRuntime
) -> *const SymblibPointResolver {
    runtime as *const SymblibPointResolver
}