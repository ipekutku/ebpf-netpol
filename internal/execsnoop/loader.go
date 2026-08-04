package execsnoop

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Event is a single execve() observation emitted by the kernel-side program.
type Event struct {
	PID  uint32
	Comm string
}

// Tracer owns the loaded BPF program, its attached tracepoint link, and the
// ring buffer reader used to pull events emitted by the kernel.
type Tracer struct {
	objs   bpfObjects
	link   link.Link
	reader *ringbuf.Reader
}

// New loads the execsnoop BPF program, attaches it to the
// syscalls/sys_enter_execve tracepoint, and opens its ring buffer for
// reading.
func New() (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading bpf objects: %w", err)
	}

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching tracepoint: %w", err)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		tp.Close()
		objs.Close()
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &Tracer{objs: objs, link: tp, reader: rd}, nil
}

// Read blocks until the next event is available, or returns
// ringbuf.ErrClosed once Close has been called.
func (t *Tracer) Read() (Event, error) {
	record, err := t.reader.Read()
	if err != nil {
		if errors.Is(err, ringbuf.ErrClosed) {
			return Event{}, err
		}
		return Event{}, fmt.Errorf("reading ringbuf record: %w", err)
	}

	var raw bpfEvent
	if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
		return Event{}, fmt.Errorf("parsing ringbuf record: %w", err)
	}

	return Event{
		PID:  raw.Pid,
		Comm: commToString(raw.Comm),
	}, nil
}

// Close releases the ring buffer reader, tracepoint link, and BPF objects.
func (t *Tracer) Close() error {
	t.reader.Close()
	t.link.Close()
	return t.objs.Close()
}

func commToString(comm [16]int8) string {
	b := make([]byte, 0, len(comm))
	for _, c := range comm {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}
