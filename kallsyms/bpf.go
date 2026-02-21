package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import (
	"context"

	"github.com/elastic/go-perf"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"golang.org/x/sys/unix"
)

// bpfUpdater is responsible for getting updates from `PERF_RECORD_KSYMBOL`.
type bpfUpdater struct {
	events []*perf.Event
}

// newBpfUpdater opens perf events for `PERF_RECORD_KSYMBOL` and starts pumping them into the provided channel.
func newBpfUpdater(ctx context.Context, cpus []int, records chan *perf.KSymbolRecord) (*bpfUpdater, error) {
	attr := new(perf.Attr)
	perf.Dummy.Configure(attr)
	attr.Options.KSymbol = true
	attr.SetWakeupWatermark(1)

	updater := &bpfUpdater{
		events: make([]*perf.Event, 0, len(cpus)),
	}

	for _, cpu := range cpus {
		event, err := perf.Open(attr, -1, cpu, nil)
		if err != nil {
			updater.Close()
			return nil, err
		}

		updater.events = append(updater.events, event)

		err = event.MapRing()
		if err != nil {
			updater.Close()
			return nil, err
		}

		err = event.Enable()
		if err != nil {
			updater.Close()
			return nil, err
		}

		go func(event *perf.Event) {
			for {
				record, err := event.ReadRecord(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}

					log.Errorf("Failed to read perf event: %v", err)
					continue
				}

				switch ksymbol := record.(type) {
				case *perf.LostRecord:
					// nil as a sentinel value to indicate lost events
					select {
					case records <- nil:
					case <-ctx.Done():
						return
					}
				case *perf.KSymbolRecord:
					if ksymbol.Type != unix.PERF_RECORD_KSYMBOL_TYPE_BPF {
						continue
					}

					select {
					case records <- ksymbol:
					case <-ctx.Done():
						return
					}
				}
			}
		}(event)
	}

	return updater, nil
}

// Close frees resources associated with bpfUpdater.
func (s *bpfUpdater) Close() {
	for _, event := range s.events {
		if err := event.Disable(); err != nil {
			log.Errorf("Failed to disable perf event: %v", err)
		}
		if err := event.Close(); err != nil {
			log.Errorf("Failed to close perf event: %v", err)
		}
	}
}
