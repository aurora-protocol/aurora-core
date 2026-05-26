package flow

import "fmt"

type SchedulerOptions struct {
	MaxBufferedBytes int
}

type StreamChunk struct {
	FlowID        uint64
	PriorityClass uint8
	Data          []byte
}

type Scheduler struct {
	maxBufferedBytes int
	bufferedBytes    int
	realtime         []StreamChunk
	interactive      []StreamChunk
	bulk             []StreamChunk
}

func NewScheduler(opts SchedulerOptions) *Scheduler {
	return &Scheduler{maxBufferedBytes: opts.MaxBufferedBytes}
}

func (s *Scheduler) Enqueue(chunk StreamChunk) error {
	if len(chunk.Data) == 0 {
		return fmt.Errorf("flow: empty stream chunk")
	}
	if s.maxBufferedBytes > 0 && s.bufferedBytes+len(chunk.Data) > s.maxBufferedBytes {
		return fmt.Errorf("flow: scheduler buffer limit exceeded")
	}
	copied := StreamChunk{
		FlowID:        chunk.FlowID,
		PriorityClass: chunk.PriorityClass,
		Data:          append([]byte(nil), chunk.Data...),
	}
	switch chunk.PriorityClass {
	case PriorityRealtime:
		s.realtime = append(s.realtime, copied)
	case PriorityInteractive:
		s.interactive = append(s.interactive, copied)
	default:
		copied.PriorityClass = PriorityBulk
		s.bulk = append(s.bulk, copied)
	}
	s.bufferedBytes += len(copied.Data)
	return nil
}

func (s *Scheduler) Next() (StreamChunk, bool) {
	if chunk, ok := popChunk(&s.realtime); ok {
		s.bufferedBytes -= len(chunk.Data)
		return chunk, true
	}
	if chunk, ok := popChunk(&s.interactive); ok {
		s.bufferedBytes -= len(chunk.Data)
		return chunk, true
	}
	if chunk, ok := popChunk(&s.bulk); ok {
		s.bufferedBytes -= len(chunk.Data)
		return chunk, true
	}
	return StreamChunk{}, false
}

func popChunk(queue *[]StreamChunk) (StreamChunk, bool) {
	if len(*queue) == 0 {
		return StreamChunk{}, false
	}
	chunk := (*queue)[0]
	*queue = (*queue)[1:]
	return chunk, true
}
