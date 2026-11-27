# Stripped Ruby discovery prototype

This branch adds a loader fallback for shared Ruby builds that hide
`ruby_current_ec`, `rb_vm_exec`, and `ruby_global_symbols`, then remove `.symtab`.
Normal symbol lookup retains precedence. Discovery uses exported functions,
instructions, anonymous TLS relocations, and the existing native unwind intervals;
it does not open separate debug files.

| Information | Discovery |
| --- | --- |
| Current EC | ARM64: common accessor called by `rb_thread_current`, `rb_fiber_current`, and `rb_current_receiver`, followed by a complete TLSDESC accessor match, or else matching inlined accessor prefixes in all three. AMD64: matching TLS accesses in `rb_thread_current` and `rb_fiber_current`, including the initialized `tls_index` offset and load displacement. |
| VM range | Unique common tail-call target of `rb_iseq_eval` and `rb_iseq_eval_main`; require an unwind interval starting at that target. |
| C-method names | Address read by `rb_sym_immortal_count`, including Ruby 4's atomic load and counter adjustment. |

AMD64 uses `amd.ExtractTLSSlot` on each candidate call sequence. ARM64 shares
the descriptor-call and thread-pointer recognition used by `arm.ExtractTLSSlot`,
but keeps interpreting after the load to verify what the helper actually returns.
Both use `tls.AnonymousSlotSymbol` to translate the slot and displacement into a
module offset. Ruby checks accessor agreement, alignment and `PT_TLS` bounds
before passing the variable to the existing `tls.Resolve`/`Locate` path. The prototype does not recover
`ruby_single_main_ractor`: TLS supplies the per-thread EC, including for Ractors.

## Scope

This is deliberately a compiler-pattern prototype. ARM64 uses bounded symbolic
matching of TLSDESC accesses in a common helper or inlined accessor prefixes. It
supports variations in register allocation and thread-pointer read ordering,
known frame instructions, and optional PAC and BTI instructions. The matcher
rejects instructions outside its explicitly supported forms.

AMD64 recognizes GNU dynamic TLS with a `LEA tls_index; CALL resolver;
MOV [RAX+offset]` sequence, allowing an optional `POP RBP` after the call. Resolver
calls can use a direct PLT call or a RIP-relative indirect GOT call, validated
against a `__tls_get_addr` relocation.

Both architectures require retained dynamic exports and native unwind metadata.
Accessor offsets must agree, even when they use different TLS descriptor slots.
Inconsistent accesses, ambiguous targets, and out-of-bounds offsets are rejected.
Unrecognized instruction patterns, other TLS dialects, stripped static
executables, and VM calls without a tail branch need further work.

## Validation

The existing `TestCoreDumps` runner loads additional `*-discovery.json` variants
of the Ruby 3.3.9, 4.0.1, and 4.0.6 shared-library fixtures on ARM64 and AMD64,
plus the ARM64 Ruby 3.3.9 Ractor fixture. These reuse the captures and expected
traces from the TLS variants, including C-method names, and set:

```json
"interpreters": {
  "ruby": {
    "disable_ec_fallback": true,
    "disable_symbol_lookup": true
  }
}
```

`disable_symbol_lookup` skips direct and fallback lookups of the internal EC,
VM and symbol-table symbols. Exported accessors and `ruby_version` remain
available. This forces the stripped-library discovery paths without modifying
the ELF modules. It uses the same per-fixture interpreter configuration as the
TLS and main-ractor fallback variants; no additional test runner or fixture
uploads are required.

Run from this worktree inside the build container:

```sh
CGO_ENABLED=1 go test ./interpreter/ruby ./tls
CGO_ENABLED=1 go -C tools/coredump test -run 'TestCoreDumps/testdata/.*/ruby-.*-discovery.json'
CGO_ENABLED=1 go -C tools/coredump test -run 'TestCoreDumps/testdata/.*/ruby-'
make lint
```

Cross-architecture core tests need a test binary matching the core architecture.
The installed stripped Debian ARM64 Ruby 3.3.8 library was also checked separately,
with auxiliary file access forbidden: EC module offset `8`, VM range
`[0x274c50, 0x274eac)`, and symbol table `0x450148` were recovered.
