package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

type gosymCmd struct {
	store    *modulestore.Store
	casePath string
}

func newGosymCmd(store *modulestore.Store) *ffcli.Command {
	args := &gosymCmd{store: store}

	set := flag.NewFlagSet("gosym", flag.ExitOnError)
	set.StringVar(&args.casePath, "case", "", "Path of the test case to debug")

	return &ffcli.Command{
		Name:       "gosym",
		Exec:       args.exec,
		ShortUsage: "gosym",
		ShortHelp:  "Symbolize go test case",
		FlagSet:    set,
	}
}

func (cmd *gosymCmd) exec(context.Context, []string) (err error) {
	// Validate arguments.
	if cmd.casePath == "" {
		return errors.New("please specify `-case`")
	}

	var test *CoredumpTestCase
	test, err = readTestCase(cmd.casePath)
	if err != nil {
		return fmt.Errorf("failed to read test case: %w", err)
	}

	if got := len(test.Modules); got != 1 {
		return fmt.Errorf("got=%d module but only 1 module is supported right now", got)
	}

	binary, err := extractModuleToTempFile(cmd.store, test.Modules[0])
	if err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}
	defer os.Remove(binary)

	addrs := map[libpf.AddressOrLineno]struct{}{}
	frames := map[libpf.AddressOrLineno][]*string{}
	for _, thread := range test.Threads {
		for i, frame := range thread.Frames {
			_, addr, err := parseUnsymbolizedFrame(frame)
			if err != nil {
				continue
			}
			addrs[addr] = struct{}{}
			frames[addr] = append(frames[addr], &thread.Frames[i])
		}
	}

	locs, err := goSymbolize(binary, addrs)
	if err != nil {
		return fmt.Errorf("failed to symbolize: %w", err)
	}

	for addr, frame := range locs {
		for _, frameS := range frames[addr] {
			*frameS = formatSymbolizedFrame(frame, false) + " (" + *frameS + ")"
		}
	}

	return writeTestCaseJSON(os.Stdout, test)
}

func extractModuleToTempFile(store *modulestore.Store, m ModuleInfo) (string, error) {
	file, err := os.CreateTemp("", "")
	if err != nil {
		return "", err
	}
	return file.Name(), store.UnpackModuleToPath(m.Ref, file.Name())
}

func goSymbolize(binary string, addrs map[libpf.AddressOrLineno]struct{}) (map[libpf.AddressOrLineno]*reporter.FrameMetadataArgs, error) {
	// Launch addr2line process.
	addr2line := exec.Command("go", "tool", "addr2line", binary)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	addr2line.Stdin = inR
	addr2line.Stdout = outW
	addr2line.Stderr = outW
	if err := addr2line.Start(); err != nil {
		return nil, err
	}

	// Transform addrs into a list. This allows us to figure out which addr2line
	// output corresponds to which address.
	addrList := make([]libpf.AddressOrLineno, 0, len(addrs))
	for pc, _ := range addrs {
		addrList = append(addrList, pc)
	}

	// Parse addr2line output and map it to addrs we were given.
	frames := map[libpf.AddressOrLineno]*reporter.FrameMetadataArgs{}
	scanCh := make(chan error)
	go func() {
		// Drain the output pipe in case we hit a parsing error.
		defer io.Copy(io.Discard, outR)

		var err error
		readFrame := addr2LineFrameReader(outR)
		for {
			var frame *reporter.FrameMetadataArgs
			frame, err = readFrame()
			if err != nil {
				break
			}
			addr := addrList[len(frames)]
			frames[addr] = frame
		}
		scanCh <- err
	}()

	// Write addrList to addr2line stdin.
	var writeErr error
	writeAddr := addr2LineAddrWriter(inW)
	for _, addr := range addrList {
		if writeErr = writeAddr(addr); writeErr != nil {
			break
		}
	}

	// Close the input pipe to signal addr2line that we're done.
	if err := inW.Close(); err != nil {
		return nil, err
		// Wait for addr2line to finish.
	} else if err := addr2line.Wait(); err != nil {
		return nil, err
		// Signal the output reader that we're done.
	} else if err := outW.Close(); err != nil {
		return nil, err
		// Wait for the output reader to finish.
	} else if err := <-scanCh; err != nil && err != io.EOF {
		return nil, err
	}
	return frames, writeErr
}

func addr2LineAddrWriter(w io.Writer) func(libpf.AddressOrLineno) error {
	return func(addr libpf.AddressOrLineno) error {
		_, err := fmt.Fprintf(w, "%x\n", addr)
		return err
	}
}

func addr2LineFrameReader(r io.Reader) func() (*reporter.FrameMetadataArgs, error) {
	scanner := bufio.NewScanner(r)
	scanErr := func() error {
		if err := scanner.Err(); err != nil {
			return err
		}
		return io.EOF
	}
	var pair [2]string
	return func() (*reporter.FrameMetadataArgs, error) {
		if !scanner.Scan() {
			return nil, scanErr()
		}
		pair[0] = scanner.Text()
		if !scanner.Scan() {
			return nil, fmt.Errorf("expected second line, but got: %w", scanErr())
		}
		pair[1] = scanner.Text()
		return linePairToFrame(pair)
	}
}

func linePairToFrame(pair [2]string) (*reporter.FrameMetadataArgs, error) {
	var frame reporter.FrameMetadataArgs
	frame.FunctionName = pair[0]
	file, line, found := strings.Cut(pair[1], ":")
	if !found {
		return nil, fmt.Errorf("expected file:line but got: %q", pair[1])
	}
	lineNum, err := strconv.Atoi(line)
	if err != nil {
		return nil, fmt.Errorf("invalid line number: %q", line)
	}
	frame.SourceFile = file
	frame.SourceLine = libpf.SourceLineno(lineNum)
	return &frame, nil
}
