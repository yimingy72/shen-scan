// Package httpadmission gates scanner HTTP writes without holding target sockets
// during quota queueing. It is shared by the Agent and its bounded Web helper.
package httpadmission

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"
)

var ErrPending = errors.New("HTTP permission not immediately available")

type Permit func(context.Context, string, string, string, bool) (time.Time, error)

type Transport struct {
	Base           *http.Transport
	Permit         Permit
	NetworkTimeout time.Duration
}

type stateKey struct{}
type requestState struct {
	ctx            context.Context
	cancel         context.CancelCauseFunc
	permit         Permit
	timeout        time.Duration
	mu             sync.Mutex
	timer          *time.Timer
	deadline       time.Time
	ip, host, port string
	err            error
	retry          bool
}

// RequestContext restores cancellation stripped by net/http's background dial
// context. It excludes this gate's own GotConn trace from permission IPC.
func RequestContext(ctx context.Context) context.Context {
	if state, ok := ctx.Value(stateKey{}).(*requestState); ok {
		return state.ctx
	}
	return ctx
}

// BeforeDial is called by the fixed-IP dialer after policy/resolution, before
// opening a target socket. No target-network timer runs during this wait.
func BeforeDial(ctx context.Context, ip, host, port string) (context.Context, error) {
	state, ok := ctx.Value(stateKey{}).(*requestState)
	if !ok {
		return ctx, nil
	}
	deadline, err := state.permit(state.ctx, ip, host, port, true)
	if err != nil {
		return state.ctx, err
	}
	if !time.Now().Before(deadline) {
		return state.ctx, errors.New("HTTP permission expired before dial")
	}
	state.mu.Lock()
	state.deadline, state.ip, state.host, state.port = deadline, ip, host, port
	if state.timer == nil {
		state.timer = time.AfterFunc(state.timeout, func() { state.cancel(context.DeadlineExceeded) })
	}
	state.mu.Unlock()
	return state.ctx, state.ctx.Err()
}

// AfterDial makes parent cancellation/network expiry close a connected socket,
// including while net/http is still performing TLS in a background dial.
func AfterDial(ctx context.Context, conn net.Conn, err error) (net.Conn, error) {
	if err != nil {
		return nil, err
	}
	if state, ok := ctx.Value(stateKey{}).(*requestState); ok {
		context.AfterFunc(state.ctx, func() { conn.Close() })
		if state.ctx.Err() != nil {
			conn.Close()
			return nil, context.Cause(state.ctx)
		}
	}
	return conn, nil
}

func (t Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t.Base == nil || t.Permit == nil || !t.Base.DisableKeepAlives {
		return nil, errors.New("HTTP admission requires a fixed dialer and disabled keepalives")
	}
	timeout := t.NetworkTimeout
	if timeout <= 0 || timeout > 8*time.Second {
		timeout = 8 * time.Second
	}
	entryCtx, endEntry := context.WithTimeout(request.Context(), 90*time.Second)
	body := request.Body
	bodyNeedsClose := true
	defer func() {
		if bodyNeedsClose && body != nil {
			body.Close()
		}
	}()
	for entryCtx.Err() == nil {
		ctx, cancel := context.WithCancelCause(entryCtx)
		state := &requestState{cancel: cancel, permit: t.Permit, timeout: timeout}
		state.ctx = context.WithValue(ctx, stateKey{}, state)
		trace := &httptrace.ClientTrace{GotConn: state.gotConn}
		outbound := request.Clone(httptrace.WithClientTrace(state.ctx, trace))
		outbound.Body = body
		bodyNeedsClose = false
		response, err := t.Base.RoundTrip(outbound)
		state.mu.Lock()
		gateErr, retry := state.err, state.retry
		state.mu.Unlock()
		if gateErr != nil {
			if response != nil {
				response.Body.Close()
			}
			state.stop()
			if retry && entryCtx.Err() == nil {
				if request.Body != nil && request.Body != http.NoBody {
					if request.GetBody == nil {
						endEntry()
						return nil, errors.New("cannot retry unsent HTTP setup with non-replayable body")
					}
					var bodyErr error
					body, bodyErr = request.GetBody()
					if bodyErr != nil {
						endEntry()
						return nil, bodyErr
					}
					bodyNeedsClose = true
				}
				continue
			}
			endEntry()
			return nil, gateErr
		}
		if err != nil {
			state.stop()
			endEntry()
			return nil, err
		}
		response.Body = &responseBody{ReadCloser: response.Body, close: func() { state.stop(); endEntry() }}
		return response, nil
	}
	endEntry()
	return nil, context.Cause(entryCtx)
}

func (state *requestState) gotConn(info httptrace.GotConnInfo) {
	state.mu.Lock()
	deadline, ip, host, port := state.deadline, state.ip, state.host, state.port
	state.mu.Unlock()
	remote, _, err := net.SplitHostPort(info.Conn.RemoteAddr().String())
	if err != nil || net.ParseIP(ip) == nil || !net.ParseIP(ip).Equal(net.ParseIP(remote)) {
		state.reject(info.Conn, fmt.Errorf("HTTP connection differs from permitted IP"), false)
		return
	}
	if state.ctx.Err() != nil {
		state.reject(info.Conn, context.Cause(state.ctx), false)
		return
	}
	if !time.Now().Before(deadline) {
		// Slow TLS is supported: obtain a fresh grant, but never queue on this socket.
		quick, stop := context.WithTimeout(state.ctx, 250*time.Millisecond)
		deadline, err = state.permit(quick, ip, host, port, false)
		quickExpired := errors.Is(quick.Err(), context.DeadlineExceeded)
		stop()
		if err != nil {
			unsent := state.ctx.Err() == nil && (errors.Is(err, ErrPending) || quickExpired)
			state.reject(info.Conn, err, unsent)
			return
		}
	}
	if state.ctx.Err() != nil {
		state.reject(info.Conn, context.Cause(state.ctx), false)
		return
	}
	if !time.Now().Before(deadline) {
		state.reject(info.Conn, ErrPending, true)
	}
}
func (state *requestState) reject(conn net.Conn, err error, retry bool) {
	// GotConn runs before net/http dispatches the request to its writer. Closing
	// first makes retry eligibility independent of cancellation select races.
	conn.Close()
	state.mu.Lock()
	state.err, state.retry = err, retry
	state.mu.Unlock()
	state.cancel(err)
}
func (state *requestState) stop() {
	state.mu.Lock()
	if state.timer != nil {
		state.timer.Stop()
	}
	state.mu.Unlock()
	state.cancel(context.Canceled)
}

type responseBody struct {
	io.ReadCloser
	close func()
}

func (body *responseBody) Close() error { err := body.ReadCloser.Close(); body.close(); return err }
