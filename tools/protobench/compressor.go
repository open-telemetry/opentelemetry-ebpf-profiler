package main

import (
	"bytes"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

type compressor interface {
	// compress compresses the content and writes it to the pre-allocated buffer.
	compress([]byte, *bytes.Buffer) (int64, error)
	id() string
}

type noneCompressor struct {
	name string
}

func (n noneCompressor) id() string { return n.name }
func (noneCompressor) compress(content []byte, _ *bytes.Buffer) (int64, error) {
	return int64(len(content)), nil
}

type gzipCompressor struct {
	name  string
	level int
}

func (g gzipCompressor) id() string { return g.name }
func (g gzipCompressor) compress(content []byte, buf *bytes.Buffer) (int64, error) {
	encoder, err := gzip.NewWriterLevel(buf, g.level)
	if err != nil {
		return 0, err
	}
	defer encoder.Close()

	if _, err = encoder.Write(content); err != nil {
		return 0, err
	}
	if err := encoder.Close(); err != nil {
		return 0, err
	}

	encoder.Flush()

	return int64(buf.Len()), nil
}

type zstdCompressor struct {
	name  string
	level zstd.EncoderLevel
}

func (z zstdCompressor) id() string { return z.name }

func (z zstdCompressor) compress(content []byte, buf *bytes.Buffer) (int64, error) {
	encoder, err := zstd.NewWriter(buf, zstd.WithEncoderLevel(z.level))
	if err != nil {
		return 0, err
	}
	defer encoder.Close()

	if _, err = encoder.Write(content); err != nil {
		return 0, err
	}

	encoder.Flush()

	return int64(buf.Len()), nil
}

type brotliCompressor struct {
	name  string
	level int
}

func (b brotliCompressor) id() string { return b.name }

func (b brotliCompressor) compress(content []byte, buf *bytes.Buffer) (int64, error) {
	encoder := brotli.NewWriterLevel(buf, b.level)
	defer encoder.Close()

	if _, err := encoder.Write(content); err != nil {
		return 0, err
	}

	encoder.Flush()

	return int64(buf.Len()), nil
}

type s2Compressor struct {
	name  string
	level s2.WriterOption
}

func (s s2Compressor) id() string { return s.name }

func (s s2Compressor) compress(content []byte, buf *bytes.Buffer) (int64, error) {
	encoder := s2.NewWriter(buf, s.level)
	defer encoder.Close()

	if _, err := encoder.Write(content); err != nil {
		return 0, err
	}

	encoder.Flush()

	return int64(buf.Len()), nil
}

type lz4Compressor struct {
	name  string
	level lz4.CompressionLevel
}

func (l lz4Compressor) id() string { return l.name }

func (l lz4Compressor) compress(content []byte, buf *bytes.Buffer) (int64, error) {
	encoder := lz4.NewWriter(buf)
	defer encoder.Close()

	err := encoder.Apply(lz4.CompressionLevelOption(l.level))
	if err != nil {
		return 0, err
	}

	if _, err = encoder.Write(content); err != nil {
		return 0, err
	}

	encoder.Flush()

	return int64(buf.Len()), nil
}
