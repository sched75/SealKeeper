package integrations

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Dispatcher fans audit events out to every enabled Sink. Push is
// non-blocking: when the internal channel is full, events are dropped and
// a counter is incremented. The drop policy is deliberate — the request
// pipeline must never wait on a slow SIEM.
type Dispatcher struct {
	repo      *Repo
	logger    *slog.Logger
	ch        chan Event
	wg        sync.WaitGroup
	cancel    context.CancelFunc
	timeoutPer time.Duration

	// Metrics (atomic so they're readable from any goroutine without lock).
	drops   atomic.Int64
	delivered atomic.Int64
	failed  atomic.Int64
}

// NewDispatcher returns a Dispatcher bound to a Repo. `bufSize` defaults to
// 256, `timeoutPer` defaults to 10s.
func NewDispatcher(repo *Repo, logger *slog.Logger, bufSize int, timeoutPer time.Duration) *Dispatcher {
	if bufSize <= 0 {
		bufSize = 256
	}
	if timeoutPer <= 0 {
		timeoutPer = 10 * time.Second
	}
	return &Dispatcher{
		repo:       repo,
		logger:     logger,
		ch:         make(chan Event, bufSize),
		timeoutPer: timeoutPer,
	}
}

// Start spawns a single worker goroutine that drains the channel until
// Stop is called. One worker is enough for v0.1 traffic; bump when you
// see Drops climb.
func (d *Dispatcher) Start(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	d.cancel = cancel
	d.wg.Add(1)
	go d.run(ctx)
}

// Stop drains the channel and waits for the worker to exit.
func (d *Dispatcher) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	d.wg.Wait()
}

// Push enqueues `ev` for delivery to every enabled sink whose filter
// matches the event type. Non-blocking — returns immediately even when
// the buffer is full (and increments the Drops counter so operators can
// see it).
func (d *Dispatcher) Push(ev Event) {
	select {
	case d.ch <- ev:
	default:
		d.drops.Add(1)
		if d.logger != nil {
			d.logger.Warn("integrations.Dispatcher: dropped event — buffer full",
				"event_type", ev.EventType, "sequence_no", ev.SequenceNo)
		}
	}
}

// Stats snapshots the lifetime counters.
type Stats struct {
	Delivered int64
	Failed    int64
	Drops     int64
}

// Stats returns a snapshot.
func (d *Dispatcher) Stats() Stats {
	return Stats{
		Delivered: d.delivered.Load(),
		Failed:    d.failed.Load(),
		Drops:     d.drops.Load(),
	}
}

// run is the worker. Reads from the channel, builds the fan-out list
// (filtered by event_type), and sends to each in parallel.
func (d *Dispatcher) run(ctx context.Context) {
	defer d.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-d.ch:
			d.deliver(ctx, ev)
		}
	}
}

func (d *Dispatcher) deliver(ctx context.Context, ev Event) {
	rows, err := d.repo.ListEnabled(ctx)
	if err != nil {
		d.logf("ListEnabled failed", "err", err)
		return
	}
	if len(rows) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, row := range rows {
		var f Filters
		if len(row.FiltersJSON) > 0 {
			_ = json.Unmarshal(row.FiltersJSON, &f)
		}
		if !f.Matches(ev.EventType) {
			continue
		}
		sink, err := BuildSink(row)
		if err != nil {
			d.logf("BuildSink failed", "integration", row.Name, "err", err)
			d.failed.Add(1)
			continue
		}
		wg.Add(1)
		go func(s Sink) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, d.timeoutPer)
			defer cancel()
			if err := s.Send(cctx, ev); err != nil {
				d.failed.Add(1)
				d.logf("sink.Send failed",
					"sink", s.Name(), "kind", string(s.Kind()), "err", err)
				return
			}
			d.delivered.Add(1)
		}(sink)
	}
	wg.Wait()
}

func (d *Dispatcher) logf(msg string, args ...any) {
	if d.logger == nil {
		return
	}
	d.logger.Warn("integrations.Dispatcher: "+msg, args...)
}

// TestSink delivers a synthetic event to `row`'s sink synchronously and
// returns the resulting error. Used by the /admin/integrations/{id}/test
// button.
func TestSink(ctx context.Context, row Integration, instanceDomain string) error {
	sink, err := BuildSink(row)
	if err != nil {
		return err
	}
	ev := NewEvent(0, "integration.test", "admin", row.Name,
		json.RawMessage(`{"hello":"from sealkeeper test event"}`),
		"", instanceDomain, time.Now())
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return sink.Send(cctx, ev)
}
