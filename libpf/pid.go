package libpf

// PID represent Unix Process ID (pid_t)
type PID uint32

func (p PID) Hash32() uint32 {
	return uint32(p)
}
