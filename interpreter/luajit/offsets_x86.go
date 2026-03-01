//go:build amd64

// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

// This is CFRAME_SIZE in src/lj_frame.h
// We could dynamically get this from lj_vm_ffi_callback disassembly and look for:
// lea rax, [rsp+CFRAME_SIZE]
// https://github.com/openresty/luajit2/blob/7952882d/src/vm_x64.dasc#L2725
const (
	cframeSize    int32 = 80
	cframeSizeJIT int32 = cframeSize + 16
)
