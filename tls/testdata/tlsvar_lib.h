/* Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TLSVAR_LIB_H
#define TLSVAR_LIB_H

// Returns where the process itself finds the variable. Its access is what emits
// the TLS relocation tls.Resolve classifies.
long *tls_var_addr(void);

// Defined by the EXTRA_HIDDEN_TLS_VAR build only.
long *other_tls_var_addr(void);

#endif
