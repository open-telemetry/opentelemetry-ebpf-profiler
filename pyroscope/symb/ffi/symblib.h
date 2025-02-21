#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


/**
 * Error codes exposed to the C API.
 *
 * The errors that we are exposing are currently rather coarsely mapped.
 * In the future, it probably makes sense to expose sub-errors more granularly.
 */
typedef enum SymblibStatus {
  Ok = 0,
  IoMisc = 1,
  IoFileNotFound = 2,
  Objfile = 3,
  Dwarf = 4,
  Symbconv = 5,
  Retpad = 6,
  BadUtf8 = 7,
  AlreadyClosed = 8,
  InvalidSymdbTablePath = 9,
  U32Overflow = 10,
} SymblibStatus;

/**
 * Read-only, nullable, owned FFI-safe string type.
 */
typedef char *SymblibString;

/**
 * FFI-safe variant of [`symbfile::LineTableEntry`].
 */
typedef struct SymblibLineTableEntry {
  uint32_t offset;
  uint32_t line_number;
} SymblibLineTableEntry;

/**
 * Read-only, owned FFI-safe owned slice type.
 *
 * The caller must ensure that `T` is FFI-safe (`#[repr(C)]`).
 */
typedef struct SymblibSlice_SymblibLineTableEntry {
  /**
   * Data pointer.
   *
   * May or may not be null for empty slices: don't rely on it.
   */
  struct SymblibLineTableEntry *data;
  /**
   * Number of entries in the slice.
   */
  size_t len;
} SymblibSlice_SymblibLineTableEntry;

/**
 * FFI-safe variant of [`symbfile::Range`].
 */
typedef struct SymblibRange {
  uint64_t elf_va;
  uint32_t length;
  SymblibString func;
  SymblibString file;
  SymblibString call_file;
  uint32_t call_line;
  uint32_t depth;
  struct SymblibSlice_SymblibLineTableEntry line_table;
} SymblibRange;

/**
 * Visitor callback for extracted ranges.
 *
 * The range is **borrowed** to the callee and the pointer is only valid for
 * the duration of the visitor call. Returning an error will abort further
 * execution and return early.
 */
typedef enum SymblibStatus (*SymblibRangeVisitor)(void *user_data, const struct SymblibRange *range);

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Extract ranges from an executable.
 *
 * This creates a [`symblib::symbconv::multi`] extractor with all supported
 * debug symbol formats registered with the following priority:
 *
 * 1) DWARF
 * 2) Go symbols
 * 3) ELF debug symbols
 * 4) ELF dynamic symbols
 *
 * This extractor is then run to completion and the visitor is invoked for
 * every range found in the executable. The user_data pointer is passed to
 * the visitor untouched and may be NULL.
 */
enum SymblibStatus symblib_rangeextr(int executable_fd,
                                     int dwarf_sup_fd,
                                     SymblibRangeVisitor visitor,
                                     void *user_data);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus
