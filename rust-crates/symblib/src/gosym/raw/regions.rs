// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//! Reference types for sub-regions of the Go runtime information.
//!
//! Most of these represent sub-regions of the `.gopclntab` section, but
//! there are some exceptions where data lives in other sections.

use super::*;
use crate::objfile;
use fallible_iterator::FallibleIterator;

/// Decoder for `.gopclntab`:`runtime.filetab`.
#[derive(Debug)]
pub struct FileNameTable<'obj>(Reader<'obj>);

impl<'obj> FileNameTable<'obj> {
    pub fn new(o: &HeaderOffsets, gopclntab: Reader<'obj>) -> Result<Self> {
        Ok(Self(gopclntab.sub_reader(o.filetab_offset.0 as usize..)?))
    }

    pub fn name(&self, offset: FileNameOffset) -> Result<&'obj str> {
        self.0.sub_reader(offset.0 as usize..)?.str()
    }
}

/// Decoder for `.gopclntab`:`runtime.cutab`.
#[derive(Debug)]
pub struct CuTable<'obj>(Reader<'obj>);

impl<'obj> CuTable<'obj> {
    pub fn new(o: &HeaderOffsets, gopclntab: Reader<'obj>) -> Result<Self> {
        gopclntab.sub_reader(o.cutab_offset.0 as usize..).map(Self)
    }

    pub fn file_name_offset(
        &self,
        cu_idx: CuTabIndex,
        fn_idx: CuTabIndex,
    ) -> Result<FileNameOffset> {
        let offs = (cu_idx.0 as u64 + fn_idx.0 as u64) * 4;
        self.0
            .sub_reader(offs as usize..)?
            .u32()
            .map(FileNameOffset)
    }
}

/// Decoder for `.gopclntab`:`runtime.funcnametab`.
#[derive(Debug)]
pub struct FuncNameTable<'obj>(Reader<'obj>);

impl<'obj> FuncNameTable<'obj> {
    pub fn new(o: &HeaderOffsets, gopclntab: Reader<'obj>) -> Result<Self> {
        gopclntab
            .sub_reader(o.funcname_offset.0 as usize..)
            .map(Self)
    }

    pub fn name(&self, offset: FuncNameOffset) -> Result<&'obj str> {
        self.0.sub_reader(offset.0 as usize..)?.str()
    }
}

/// Decoder for `.gopclntab`:`runtime.pctab`.
///
/// Note that while Go calls this a "table" it is actually just a
/// concatenation of `pcdata` sequences (see [`PcDataReader`]).
#[derive(Debug)]
pub struct PcTable<'obj>(Reader<'obj>);

impl<'obj> PcTable<'obj> {
    pub fn new(o: &HeaderOffsets, gopclntab: Reader<'obj>) -> Result<Self> {
        gopclntab.sub_reader(o.pctab_offset.0 as usize..).map(Self)
    }

    pub fn pcdata(&self, offset: PcTabOffset) -> Result<PcDataReader<'obj>> {
        self.0
            .sub_reader(offset.0 as usize..)
            .map(PcDataReader::new)
    }
}

/// Decoder for `.gopclntab`:`runtime.functab`.
///
/// `runtime.functab`, in this case, refers to the label with that name that
/// the linker emits, not the structure type with the same name.
#[derive(Debug)]
pub struct FuncTable<'obj> {
    reader: Reader<'obj>,
    num_funcs: u64,
}

impl<'obj> FuncTable<'obj> {
    pub fn new(o: &HeaderOffsets, gopclntab: Reader<'obj>) -> Result<Self> {
        Ok(Self {
            reader: gopclntab.sub_reader(o.pcln_offset.0 as usize..)?,
            num_funcs: o.num_funcs,
        })
    }

    pub fn index_iter(&self) -> Result<FuncIndexIter<'obj>> {
        let sz = FuncTabIndexEntry::size_of(self.reader.header());
        let reader = self.reader.sub_reader(..sz * self.num_funcs as usize)?;
        Ok(FuncIndexIter(reader))
    }

    pub fn func(&self, offs: FuncTabOffset) -> Result<Func<'obj>> {
        Func::read(self.reader.sub_reader(offs.0 as usize..)?)
    }
}

/// Iterator over the index in `.gopclntab`:`runtime.functab`.
#[derive(Debug)]
pub struct FuncIndexIter<'obj>(Reader<'obj>);

impl FallibleIterator for FuncIndexIter<'_> {
    type Item = FuncTabIndexEntry;
    type Error = Error;

    fn next(&mut self) -> Result<Option<Self::Item>> {
        if self.0.is_empty() {
            return Ok(None);
        }

        FuncTabIndexEntry::read(&mut self.0).map(Some)
    }
}

/// Decoder for the `go:func.*` region.
#[derive(Debug)]
pub enum FuncData<'obj> {
    /// `go:func.*` references are absolute pointers (Go < 1.18).
    Global(Header, objfile::MemoryMap<'obj>),

    /// `go:func.*` references are relative to `gofunc` field in module data (Go >= 1.18).
    GoFunc(Reader<'obj>),
}

impl<'obj> FuncData<'obj> {
    fn mk_reader(&self, fdref: FuncDataRef) -> Result<Reader<'obj>> {
        match (fdref, self) {
            (FuncDataRef::Addr(abs), FuncData::Global(header, mem)) => {
                let sec = mem.section_for_addr(abs).ok_or(Error::InvalidPtr)?;
                let slice = sec.as_obj_slice().ok_or(Error::CannotAvoidCopy)?;
                let sub = &slice[abs as usize - sec.virt_addr() as usize..];
                Ok(Reader::new(*header, abs, sub))
            }
            (FuncDataRef::Offs(offs), FuncData::GoFunc(gofunc)) => {
                Ok(gofunc.sub_reader(offs.0 as usize..)?)
            }
            _ => unreachable!("bug: invalid addr/offs global/gofunc combination"),
        }
    }

    pub fn inlined_call(&self, tree: FuncDataRef, idx: InlineTreeIndex) -> Result<InlinedCall> {
        let mut reader = self.mk_reader(tree)?;
        let sz = InlinedCall::size_of(reader.header());
        reader.skip(idx.0 as usize * sz);
        InlinedCall::read(reader)
    }
}
