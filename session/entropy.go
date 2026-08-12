package session

import (
	"context"
	"crypto/rand"
	"fmt"
	"reflect"
	"sync"
)

// EntropySource fills p without retaining it and returns promptly when ctx is canceled.
type EntropySource interface {
	ReadContext(context.Context, []byte) error
}

type systemEntropySource struct {
	requests chan<- systemEntropyRequest
}

type systemEntropyRequest struct {
	ctx      context.Context
	length   int
	response chan<- systemEntropyResult
}

type systemEntropyResult struct {
	value []byte
	err   error
}

var (
	defaultEntropyOnce     sync.Once
	defaultEntropyRequests chan systemEntropyRequest
)

func (s systemEntropySource) ReadContext(ctx context.Context, p []byte) error {
	if ctx == nil {
		return fmt.Errorf("session: nil entropy context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(p) == 0 {
		return nil
	}
	requests := s.requests
	if requests == nil {
		requests = defaultSystemEntropyRequests()
	}
	response := make(chan systemEntropyResult)
	request := systemEntropyRequest{ctx: ctx, length: len(p), response: response}
	select {
	case requests <- request:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case result := <-response:
		defer zeroBytes(result.value)
		if result.err != nil {
			return result.err
		}
		if len(result.value) != len(p) {
			return fmt.Errorf("session: incomplete system entropy result")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		copy(p, result.value)
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

func defaultSystemEntropyRequestsChannel() chan systemEntropyRequest {
	defaultEntropyOnce.Do(func() {
		defaultEntropyRequests = make(chan systemEntropyRequest)
		go runSystemEntropyBroker(defaultEntropyRequests)
	})
	return defaultEntropyRequests
}

func defaultSystemEntropyRequests() chan<- systemEntropyRequest {
	return defaultSystemEntropyRequestsChannel()
}

func runSystemEntropyBroker(requests <-chan systemEntropyRequest) {
	for request := range requests {
		if request.ctx.Err() != nil {
			continue
		}
		value := make([]byte, request.length)
		_, err := rand.Read(value)
		result := systemEntropyResult{value: value, err: err}
		select {
		case request.response <- result:
		case <-request.ctx.Done():
			zeroBytes(value)
		}
	}
}

func normalizeEntropy(source EntropySource) (EntropySource, error) {
	if source == nil {
		return systemEntropySource{}, nil
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if value.IsNil() {
			return nil, fmt.Errorf("session: nil entropy source")
		}
	}
	return source, nil
}

func (a *Application) readNonce(ctx context.Context) ([]byte, error) {
	readCtx, cancel := context.WithCancel(ctx)
	stopLifecycleCancel := context.AfterFunc(a.lifecycleCtx, cancel)
	defer func() {
		stopLifecycleCancel()
		cancel()
	}()

	select {
	case <-readCtx.Done():
		return nil, readCtx.Err()
	case <-a.entropyGate:
	}
	defer func() { a.entropyGate <- struct{}{} }()

	nonce := make([]byte, keyUpdateNonceBytes)
	if err := a.entropy.ReadContext(readCtx, nonce); err != nil {
		zeroBytes(nonce)
		return nil, err
	}
	if err := readCtx.Err(); err != nil {
		zeroBytes(nonce)
		return nil, err
	}
	return nonce, nil
}
