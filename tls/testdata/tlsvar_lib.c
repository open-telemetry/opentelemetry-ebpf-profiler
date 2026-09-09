// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// The thread-locals under test, built by the Makefile into every TLS access
// model, dialect and libc combination.

#include "tlsvar_lib.h"

// Unreferenced, and initialized so it takes .tdata ahead of the .tbss
// variables below: it keeps tls_var off offset 0 within PT_TLS, where an offset
// the loader folds in and one added twice are indistinguishable.
__thread long tls_pad = 0x7c7c;

// Hidden visibility is what lets the compiler emit the local-dynamic model:
// a default-visibility symbol is preemptible and so can never use it.
#ifdef HIDDEN_TLS
__attribute__((visibility("hidden")))
#endif
__thread long tls_var;

// Any access emits the relocation, and returning the address is what stops the
// optimiser dropping it. NO_REFERENCE leaves the variable defined but
// unreferenced, the one shape with no access model.
#ifndef NO_REFERENCE
long *tls_var_addr(void) {
  return &tls_var;
}
#endif

#ifdef BIG_TLS
// Initialized, so it takes .tdata, which precedes the .tbss the variables land
// in whatever the order here, and large enough to push their TP offsets past
// tls.minUserAddr. That is what makes locateTLSDesc ask the resolver instead of
// settling the argument by magnitude.
__thread long tls_big_pad[16384] = {1};
#endif

#ifdef EXTRA_HIDDEN_TLS_VAR
// A second hidden thread-local, so the addend rule for a symbol-less
// relocation has two variables to separate.
__attribute__((visibility("hidden"))) __thread long other_tls_var;

long *other_tls_var_addr(void) {
  return &other_tls_var;
}
#endif
