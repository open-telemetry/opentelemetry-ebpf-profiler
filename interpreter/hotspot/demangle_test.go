/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package hotspot

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJavaDemangling(t *testing.T) {
	cases := []struct {
		klass, method, signature, demangled string
	}{
		{"java/lang/Object", "<init>", "()V",
			"void java.lang.Object.<init>()"},
		{"java/lang/StringLatin1", "equals", "([B[B)Z",
			"boolean java.lang.StringLatin1.equals(byte[], byte[])"},
		{"java/util/zip/ZipUtils", "CENSIZ", "([BI)J",
			"long java.util.zip.ZipUtils.CENSIZ(byte[], int)"},
		{"java/util/regex/Pattern$BmpCharProperty", "match",
			"(Ljava/util/regex/Matcher;ILjava/lang/CharSequence;)Z",
			"boolean java.util.regex.Pattern$BmpCharProperty.match" +
				"(java.util.regex.Matcher, int, java.lang.CharSequence)"},
		{"java/lang/AbstractStringBuilder", "appendChars", "(Ljava/lang/String;II)V",
			"void java.lang.AbstractStringBuilder.appendChars" +
				"(java.lang.String, int, int)"},
		{"foo/test", "bar", "([)J", "long foo.test.bar()"},
	}

	for _, c := range cases {
		demangled := demangleJavaMethod(c.klass, c.method, c.signature)
		assert.Equal(t, c.demangled, demangled)
	}
}
