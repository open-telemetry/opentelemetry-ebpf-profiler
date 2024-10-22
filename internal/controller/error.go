package controller // import "go.opentelemetry.io/ebpf-profiler/internal/controller"

// ErrorWithExitCode provides an error with an exit code
// Used to be able to return errors with the exit code the CLI is expected to
// return when exiting.
type ErrorWithExitCode struct {
	error
	code int
}

func (e ErrorWithExitCode) Code() int {
	return e.code
}
