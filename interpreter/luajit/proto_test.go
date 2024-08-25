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

package luajit

import (
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// literal go
// add commas between each element
//
//nolint:lll
const bytes = "105 110 112 117 116 0 0 99 108 101 110 0 14 85 100 105 99 116 0 8 77 97 0 2 75 98 0 0 75 114 101 115 117 108 116 0 1 74 114 101 115 117 108 116 108 101 110 0 1 73 110 0 1 72 119 111 114 100 0 1 71 1 3 49 2 0 49 3 0 49 105 0 1 47 99 0 5 42 119 99 0 3 39 119 114 105 116 101 0 12 25 0"

func TestParseVarinfo(t *testing.T) {
	strs := strings.Split(bytes, " ")
	b := make([]byte, len(strs))
	for i, s := range strs {
		num, err := strconv.ParseInt(s, 10, 8)
		require.NoError(t, err)
		b[i] = byte(num)
	}
	str := parseVarinfo(b, 2, 0)
	t.Log(str)
	str = parseVarinfo(b, 14, 1)
	t.Log(str)
	str = parseVarinfo(b, 23, 2)
	t.Log(str)
	str = parseVarinfo(b, 40, 3)
	t.Log(str)
	str = parseVarinfo(b, 40, 4)
	t.Log(str)
	str = parseVarinfo(b, 40, 5)
	t.Log(str)
	str = parseVarinfo(b, 40, 6)
	t.Log(str)
	str = parseVarinfo(b, 40, 7)
	t.Log(str)
	str = parseVarinfo(b, 40, 8)
	t.Log(str)
	str = parseVarinfo(b, 40, 9)
	t.Log(str)
	str = parseVarinfo(b, 40, 10)
	t.Log(str)
	str = parseVarinfo(b, 40, 11)
	t.Log(str)
	str = parseVarinfo(b, 40, 12)
	t.Log(str)
	str = parseVarinfo(b, 40, 13)
	t.Log(str)
	str = parseVarinfo(b, 40, 14)
	t.Log(str)
	str = parseVarinfo(b, 60, 15)
	t.Log(str)
	str = parseVarinfo(b, 60, 16)
	t.Log(str)
}
