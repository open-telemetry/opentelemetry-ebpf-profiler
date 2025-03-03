// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

use crate::{StatusCode, SymblibSlice, SymblibString};
use symblib::symbconv;
use symblib::symbconv::PointResolver;
use symblib::VirtAddr;

#[repr(C)]
#[derive(Debug)]
pub struct SymblibResolvedSymbol {
    pub start_addr: VirtAddr,
    pub function_name: SymblibString,
    pub file_names: SymblibSlice<SymblibString>,
    pub line_numbers: SymblibSlice<u32>,
}

impl From<symbconv::ResolvedSymbol> for SymblibResolvedSymbol {
    fn from(sym: symbconv::ResolvedSymbol) -> Self {
        let file_names: Vec<SymblibString> = sym
            .file_names
            .unwrap_or_default()
            .into_iter()
            .map(Into::into)
            .collect();

        let line_numbers: Vec<u32> = sym.line_numbers.unwrap_or_default();

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

impl SymblibPointResolver {
    pub fn new(resolver: Box<dyn PointResolver + Send>) -> Self {
        Self { inner: resolver }
    }
}

#[no_mangle]
pub extern "C" fn symblib_point_resolver_symbols_for_pc(
    resolver: &SymblibPointResolver,
    pc: VirtAddr,
    out_symbols: *mut *mut SymblibSlice<SymblibResolvedSymbol>,
) -> StatusCode {
    let symbols: Vec<_> = match resolver.inner.symbols_for_pc(pc) {
        Ok(syms) => syms.into_iter().map(Into::into).collect(),
        Err(e) => return StatusCode::from(e),
    };

    unsafe {
        *out_symbols = Box::into_raw(Box::new(symbols.into()));
    }
    StatusCode::Ok
}

#[no_mangle]
pub extern "C" fn symblib_slice_symblibresolved_symbol_free(
    slice: *mut SymblibSlice<SymblibResolvedSymbol>,
) {
    if !slice.is_null() {
        unsafe {
            drop(Box::from_raw(slice));
        }
    }
}
