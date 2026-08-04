// Command netguard is the netguard control plane. At M0 it does nothing
// more than load internal/execsnoop and print the events it emits, as a
// toolchain smoke test.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ipekutku/ebpf-netpol/internal/execsnoop"
)

func main() {
	tracer, err := execsnoop.New()
	if err != nil {
		log.Fatalf("starting tracer: %v", err)
	}
	defer tracer.Close()

	log.Println("netguard: attached to syscalls/sys_enter_execve, waiting for events (Ctrl-C to stop)")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		tracer.Close()
	}()

	for {
		event, err := tracer.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("reading event: %v", err)
			continue
		}
		log.Printf("execve: pid=%d comm=%q", event.PID, event.Comm)
	}
}
