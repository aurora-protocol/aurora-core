package handshake

import (
	"context"
	"fmt"
	"sync"

	"github.com/aurora-protocol/aurora-core/protocol"
)

// ClientHandshake owns a client handshake paused after Prelude1 verification.
// Complete transfers the established session to its caller; Close cancels and
// destroys an incomplete handshake.
type ClientHandshake struct {
	provider *deferredClientProofProvider
	cancel   context.CancelFunc
	done     chan struct{}

	mu                sync.Mutex
	completionClaimed bool
	closed            bool
	result            clientHandshakeResult
}

type clientHandshakeResult struct {
	session *EstablishedSession
	err     error
}

type clientProofResult struct {
	admission protocol.AdmissionProof
	replay    protocol.ReplayProof
}

type deferredClientProofProvider struct {
	stateMu   sync.Mutex
	shutdown  bool
	requests  chan ClientProofRequest
	results   chan clientProofResult
	closed    chan struct{}
	closeOnce sync.Once
}

// Begin opens and authenticates the carrier through Prelude1, then returns the
// exact context required to obtain the admission proof. It does not send a
// capsule or acquire application streams until Complete is called.
func (d *ClientDriver) Begin(ctx context.Context, opener ClientCarrierOpener) (*ClientHandshake, ClientProofRequest, error) {
	if d == nil {
		return nil, ClientProofRequest{}, fmt.Errorf("handshake: nil client driver")
	}
	if ctx == nil {
		return nil, ClientProofRequest{}, fmt.Errorf("handshake: nil client context")
	}
	if err := ctx.Err(); err != nil {
		return nil, ClientProofRequest{}, err
	}
	if isNilDependency(opener) {
		return nil, ClientProofRequest{}, fmt.Errorf("handshake: missing client carrier opener")
	}

	provider := &deferredClientProofProvider{
		requests: make(chan ClientProofRequest, 1),
		results:  make(chan clientProofResult, 1),
		closed:   make(chan struct{}),
	}
	connectContext, cancel := context.WithCancel(ctx)
	handshake := &ClientHandshake{
		provider: provider,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	driver := *d
	driver.proofProvider = provider
	go func() {
		session, err := driver.Connect(connectContext, opener)
		handshake.storeResult(clientHandshakeResult{session: session, err: err})
	}()

	select {
	case request := <-provider.requests:
		return handshake, cloneClientProofRequestValue(request), nil
	case <-handshake.done:
		result := handshake.resultValue()
		handshake.markClosed()
		if result.session != nil {
			_ = result.session.Close()
		}
		if result.err == nil {
			result.err = fmt.Errorf("handshake: client handshake completed before proof request")
		}
		return nil, ClientProofRequest{}, result.err
	case <-ctx.Done():
		_ = handshake.Close()
		return nil, ClientProofRequest{}, ctx.Err()
	}
}

// Complete supplies the issuer-bound proofs, completes the capsule exchange,
// and transfers application-session ownership to the caller.
func (h *ClientHandshake) Complete(ctx context.Context, admissionProof protocol.AdmissionProof, replayProof protocol.ReplayProof) (*EstablishedSession, error) {
	if h == nil {
		return nil, fmt.Errorf("handshake: nil client handshake")
	}
	if ctx == nil {
		return nil, fmt.Errorf("handshake: nil client completion context")
	}
	if err := ctx.Err(); err != nil {
		_ = h.Close()
		return nil, err
	}
	if err := h.claimCompletion(); err != nil {
		return nil, err
	}
	if err := h.provider.complete(admissionProof, replayProof); err != nil {
		_ = h.Close()
		return nil, err
	}

	select {
	case <-h.done:
		result := h.resultValue()
		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			if result.session != nil {
				_ = result.session.Close()
			}
			return nil, fmt.Errorf("handshake: client handshake is closed")
		}
		h.closed = true
		h.mu.Unlock()
		if result.err != nil {
			return nil, result.err
		}
		if result.session == nil {
			return nil, fmt.Errorf("handshake: client handshake completed without application session")
		}
		return result.session, nil
	case <-ctx.Done():
		_ = h.Close()
		return nil, ctx.Err()
	}
}

// Close is idempotent. It does not close a session already returned by Complete.
func (h *ClientHandshake) Close() error {
	if h == nil {
		return nil
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.mu.Unlock()
	h.provider.close()
	h.cancel()
	<-h.done
	result := h.resultValue()
	if result.session != nil {
		return result.session.Close()
	}
	return nil
}

func (h *ClientHandshake) claimCompletion() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.completionClaimed {
		return fmt.Errorf("handshake: client handshake is closed")
	}
	h.completionClaimed = true
	return nil
}

func (h *ClientHandshake) storeResult(result clientHandshakeResult) {
	h.mu.Lock()
	h.result = result
	close(h.done)
	h.mu.Unlock()
}

func (h *ClientHandshake) resultValue() clientHandshakeResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.result
}

func (h *ClientHandshake) markClosed() {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
}

func (p *deferredClientProofProvider) BuildProofs(ctx context.Context, request ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	if p == nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("handshake: deferred client proof provider is missing")
	}
	request = cloneClientProofRequestValue(request)
	defer zeroClientProofRequest(&request)
	select {
	case p.requests <- request:
	case <-p.closed:
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("handshake: client handshake closed before proofs")
	case <-ctx.Done():
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, ctx.Err()
	}
	select {
	case result := <-p.results:
		return result.admission, result.replay, nil
	case <-p.closed:
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("handshake: client handshake closed before proofs")
	case <-ctx.Done():
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, ctx.Err()
	}
}

func (p *deferredClientProofProvider) complete(admissionProof protocol.AdmissionProof, replayProof protocol.ReplayProof) error {
	if p == nil {
		return fmt.Errorf("handshake: deferred client proof provider is missing")
	}
	admission, err := cloneAdmissionProof(admissionProof)
	if err != nil {
		return fmt.Errorf("handshake: clone supplied admission proof: %w", err)
	}
	replay, err := cloneReplayProof(replayProof)
	if err != nil {
		zeroAdmissionProof(&admission)
		return fmt.Errorf("handshake: clone supplied replay proof: %w", err)
	}
	result := clientProofResult{admission: admission, replay: replay}
	p.stateMu.Lock()
	if p.shutdown {
		p.stateMu.Unlock()
		zeroClientProofResult(&result)
		return fmt.Errorf("handshake: client handshake is closed")
	}
	select {
	case p.results <- result:
		p.stateMu.Unlock()
		return nil
	default:
		p.stateMu.Unlock()
		zeroClientProofResult(&result)
		return fmt.Errorf("handshake: client proof result is already pending")
	}
}

func (p *deferredClientProofProvider) close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		p.stateMu.Lock()
		p.shutdown = true
		close(p.closed)
		select {
		case result := <-p.results:
			zeroClientProofResult(&result)
		default:
		}
		p.stateMu.Unlock()
	})
}

func zeroClientProofResult(value *clientProofResult) {
	if value == nil {
		return
	}
	zeroAdmissionProof(&value.admission)
	zeroReplayProof(&value.replay)
	*value = clientProofResult{}
}
