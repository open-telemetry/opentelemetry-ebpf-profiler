package customlabelstest

import (
	"context"
	"os/exec"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

func TestNativeCustomLabels(t *testing.T) {
	if !testutils.IsRoot() {
		t.Skip("root privileges required")
	}

	r := &testutils.MockReporter{}
	enabledTracers, _ := tracertypes.Parse("all")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	traceCh, _ := testutils.StartTracer(ctx, t, enabledTracers, r, false)
	// TODO - change this to `cargo build --release --bin custom-labels-example`
	// once we have the Rust workspace from upstream.
	cmd := exec.Command("cargo", "build", "--release",
		"--manifest-path", "./rust-crates/custom-labels-example/Cargo.toml")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	errCh := make(chan error, 1)

	cmd = exec.CommandContext(ctx,
		"./rust-crates/custom-labels-example/target/release/custom-labels-example")
	err = cmd.Start()
	require.NoError(t, err)

	go func() {
		err := cmd.Wait()
		errCh <- err
	}()

	stopCh := time.After(10 * time.Second)

	re := regexp.MustCompile(`^[a-zA-Z0-9]{16}$`)
	good := false
Loop:
	for {
		select {
		case trace, ok := <-traceCh:
			if !ok {
				break Loop
			}
			t.Logf("got a trace %s", trace.Comm)
			if len(trace.CustomLabels) > 0 {
				var gotL1, gotL2 bool
				for k, v := range trace.CustomLabels {
					switch k {
					case "l1":
						gotL1 = true
						require.True(t, re.MatchString(v))
						t.Logf("got l1, value is %s", v)
					case "l2":
						gotL2 = true
						require.True(t, re.MatchString(v))
						t.Logf("got l2, value is %s", v)
					default:
						require.Failf(t, "fail", "got unexpected label: %s=%s", k, v)
					}
				}
				if gotL1 && gotL2 {
					good = true
					break Loop
				}
			}
		case err := <-errCh:
			require.Failf(t, "fail", "Failed to run custom-labels-example, err = %v", err)
		case <-stopCh:
			require.Fail(t, "fail", "Failed to get labels after ten seconds")
		}
	}
	require.True(t, good)
}
