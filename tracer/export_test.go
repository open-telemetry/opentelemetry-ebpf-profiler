package tracer

// As RewriteMaps() was deprecated in cilium/ebpf we do not
// want to export this function and make it part of the public
// API of tracer, so make it available just for testing.
var RewriteMaps = rewriteMaps
