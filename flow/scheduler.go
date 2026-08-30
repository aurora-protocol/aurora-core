package flow

import "fmt"

type SchedulerOptions struct {
	MaxBufferedBytes int
}

type StreamChunk struct {
	FlowID        uint64
	PriorityClass uint8
	Data          []byte
	Flags         uint64
}

// maximumPriorityBurst bounds how many chunks a priority class may take while
// a lower class has data waiting. Without it a flow that keeps its class
// saturated shuts the classes below it out of the tunnel indefinitely.
const maximumPriorityBurst = 4

type Scheduler struct {
	maxBufferedBytes int
	bufferedBytes    int
	realtime         []StreamChunk
	interactive      []StreamChunk
	bulk             []StreamChunk
	// passedOver counts the chunks a higher class has taken while the queue at
	// the same index held data, so a starved class can claim its turn.
	passedOver [3]int
}

func NewScheduler(opts SchedulerOptions) *Scheduler {
	return &Scheduler{maxBufferedBytes: opts.MaxBufferedBytes}
}

func (s *Scheduler) Enqueue(chunk StreamChunk) error {
	if len(chunk.Data) == 0 {
		return fmt.Errorf("flow: empty stream chunk")
	}
	if s.maxBufferedBytes > 0 {
		if s.bufferedBytes < 0 || s.bufferedBytes > s.maxBufferedBytes || len(chunk.Data) > s.maxBufferedBytes-s.bufferedBytes {
			return fmt.Errorf("flow: scheduler buffer limit exceeded")
		}
	}
	copied := StreamChunk{
		FlowID:        chunk.FlowID,
		PriorityClass: chunk.PriorityClass,
		Data:          append([]byte(nil), chunk.Data...),
		Flags:         chunk.Flags,
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
	index, ok := s.nextQueueIndex()
	if !ok {
		return StreamChunk{}, false
	}
	chunk, _ := popChunk(s.queueAt(index))
	s.bufferedBytes -= len(chunk.Data)
	s.passedOver[index] = 0
	for lower := index + 1; lower < len(s.passedOver); lower++ {
		if len(*s.queueAt(lower)) != 0 {
			s.passedOver[lower]++
		}
	}
	return chunk, true
}

// nextQueueIndex reports the queue to serve. The highest priority non-empty
// queue wins, unless a lower one has been passed over maximumPriorityBurst
// times while holding data, in which case the most starved queue goes first.
func (s *Scheduler) nextQueueIndex() (int, bool) {
	for index := len(s.passedOver) - 1; index >= 0; index-- {
		if s.passedOver[index] >= maximumPriorityBurst && len(*s.queueAt(index)) != 0 {
			return index, true
		}
	}
	for index := range s.passedOver {
		if len(*s.queueAt(index)) != 0 {
			return index, true
		}
	}
	return 0, false
}

func (s *Scheduler) queueAt(index int) *[]StreamChunk {
	switch index {
	case 0:
		return &s.realtime
	case 1:
		return &s.interactive
	}
	return &s.bulk
}

func popChunk(queue *[]StreamChunk) (StreamChunk, bool) {
	if len(*queue) == 0 {
		return StreamChunk{}, false
	}
	chunks := *queue
	chunk := chunks[0]
	chunks[0] = StreamChunk{}
	if len(chunks) == 1 {
		*queue = chunks[:0]
	} else {
		*queue = chunks[1:]
	}
	return chunk, true
}
