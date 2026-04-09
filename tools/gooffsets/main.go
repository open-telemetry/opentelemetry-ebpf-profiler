package main

import (
	"debug/buildinfo"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/mod/semver"
)

type goLabelsOffsets struct {
	mOffset             uint32
	curg                uint32
	labels              uint32
	hmapCount           uint32
	hmapLog2BucketCount uint32
	hmapBuckets         uint32
	schedSp             uint32
	schedPc             uint32
	schedBp             uint32
}

func getOffsets(f *elf.File, version string) (*goLabelsOffsets, error) {
	d, err := f.DWARF()
	if err != nil {
		return nil, err
	}

	r := d.Reader()
	g, err := ReadEntry(r, "runtime.g", dwarf.TagStructType)
	if err != nil {
		return nil, err
	}
	if g == nil {
		return nil, errors.New("type runtime.g not found")
	}
	// ReadChildTypeAndOffset repositions the reader to the field's type entry, so
	// we re-seek to g.Offset before each sequential read from g's children.
	r.Seek(g.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	mPType, mOffset, err := ReadChildTypeAndOffset(r, "m")
	if err != nil {
		return nil, err
	}
	if mPType.Tag != dwarf.TagPointerType {
		return nil, errors.New("type of m in runtime.g is not a pointer")
	}

	// Read g.sched.sp and g.sched.pc: sched is a gobuf struct embedded in g.
	r.Seek(g.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	schedType, schedOffset, err := ReadChildTypeAndOffset(r, "sched")
	if err != nil {
		return nil, err
	}
	r.Seek(schedType.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, schedSpOff, err := ReadChildTypeAndOffset(r, "sp")
	if err != nil {
		return nil, err
	}
	r.Seek(schedType.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, schedPcOff, err := ReadChildTypeAndOffset(r, "pc")
	if err != nil {
		return nil, err
	}
	r.Seek(schedType.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, schedBpOff, err := ReadChildTypeAndOffset(r, "bp")
	if err != nil {
		return nil, err
	}
	r.Seek(schedType.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	mType, err := ReadType(r, mPType)
	if err != nil {
		return nil, err
	}

	r.Seek(mType.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	curgPType, curgOffset, err := ReadChildTypeAndOffset(r, "curg")
	if err != nil {
		return nil, err
	}
	if curgPType.Tag != dwarf.TagPointerType {
		return nil, errors.New("type of curg in m is not a pointer")
	}
	_, err = ReadType(r, curgPType)
	if err != nil {
		return nil, err
	}

	_, labelsOffset, err := ReadChildTypeAndOffset(r, "labels")
	if err != nil {
		return nil, err
	}

	hmap, err := ReadEntry(r, "runtime.hmap", dwarf.TagStructType)
	if err != nil {
		return nil, err
	}

	if semver.Compare(version, "v1.24.0") >= 0 {
		return &goLabelsOffsets{
			mOffset: uint32(mOffset),
			curg:    uint32(curgOffset),
			labels:  uint32(labelsOffset),
			schedSp: uint32(schedOffset + schedSpOff),
			schedPc: uint32(schedOffset + schedPcOff),
			schedBp: uint32(schedOffset + schedBpOff),
		}, nil
	}

	_, countOffset, err := ReadChildTypeAndOffset(r, "count")
	if err != nil {
		return nil, err
	}
	r.Seek(hmap.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, bOffset, err := ReadChildTypeAndOffset(r, "B")
	if err != nil {
		return nil, err
	}
	r.Seek(hmap.Offset)
	_, err = r.Next()
	if err != nil {
		return nil, err
	}
	_, bucketsOffset, err := ReadChildTypeAndOffset(r, "buckets")
	if err != nil {
		return nil, err
	}

	return &goLabelsOffsets{
		mOffset:             uint32(mOffset),
		curg:                uint32(curgOffset),
		labels:              uint32(labelsOffset),
		hmapCount:           uint32(countOffset),
		hmapLog2BucketCount: uint32(bOffset),
		hmapBuckets:         uint32(bucketsOffset),
		schedSp:             uint32(schedOffset + schedSpOff),
		schedPc:             uint32(schedOffset + schedPcOff),
		schedBp:             uint32(schedOffset + schedBpOff),
	}, nil
}

func open(path string) (*elf.File, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		_ = ef.Close()
		return nil, "", err
	}
	bi, err := buildinfo.Read(f)
	if err != nil {
		return nil, "", err
	}
	return ef, bi.GoVersion, nil
}

func convertToSemver(goVersion string) string {
	version := strings.TrimPrefix(goVersion, "go")

	return "v" + version
}

func main() {
	f, version, err := open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	offs, err := getOffsets(f, convertToSemver(version))
	if err != nil {
		panic(err)
	}
	fmt.Printf(`"%s": {
`, version)
	fmt.Printf("\tm_offset:               %d,\n", offs.mOffset)
	fmt.Printf("\tcurg:                   %d,\n", offs.curg)
	fmt.Printf("\tlabels:                 %d,\n", offs.labels)
	fmt.Printf("\thmap_count:             %d,\n", offs.hmapCount)
	fmt.Printf("\thmap_log2_bucket_count: %d,\n", offs.hmapLog2BucketCount)
	fmt.Printf("\thmap_buckets:           %d,\n", offs.hmapBuckets)
	fmt.Printf("\tsched_sp:               %d,\n", offs.schedSp)
	fmt.Printf("\tsched_pc:               %d,\n", offs.schedPc)
	fmt.Printf("\tsched_bp:               %d,\n", offs.schedBp)
	fmt.Println("},")
}
