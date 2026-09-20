package engine

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

type WorkerRPCMessage struct {
	RequestID       string             `json:"request_id"`
	Method          string             `json:"method"`
	Host            string             `json:"host,omitempty"`
	Port            int                `json:"port,omitempty"`
	Route           string             `json:"route,omitempty"`
	ProxyEndpoint   string             `json:"proxy_endpoint,omitempty"`
	AllowPrivate    bool               `json:"allow_private,omitempty"`
	DeadlineMs      int64              `json:"deadline_ms,omitempty"`
	Accepted           bool               `json:"accepted,omitempty"`
	Errors             []string           `json:"errors,omitempty"`
	IsExtraTrustAnchor bool               `json:"is_extra_trust_anchor,omitempty"`
	ExtraAnchorSubject string             `json:"extra_anchor_subject,omitempty"`
	DERChainBase64     []string           `json:"der_chain_base64,omitempty"`
	NativeResult       *NativeTrustResult `json:"native_result,omitempty"`
	Outcome            *ProbeOutcome      `json:"outcome,omitempty"`
	ErrorCode          string             `json:"error_code,omitempty"`
	ErrorMessage       string             `json:"error_message,omitempty"`
}

type CoreWorkerServer struct {
	inReader      *bufio.Reader
	outWriter     io.Writer
	writeLock     sync.Mutex
	pendingTrust  map[string]chan *NativeTrustResult
	trustLock     sync.Mutex
	workerPoolSem chan struct{}
}

func NewCoreWorkerServer(r io.Reader, w io.Writer, concurrency int) *CoreWorkerServer {
	if concurrency <= 0 {
		concurrency = 4
	}
	return &CoreWorkerServer{
		inReader:      bufio.NewReader(r),
		outWriter:     w,
		pendingTrust:  make(map[string]chan *NativeTrustResult),
		workerPoolSem: make(chan struct{}, concurrency),
	}
}

func (s *CoreWorkerServer) writeMessage(msg *WorkerRPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	s.writeLock.Lock()
	defer s.writeLock.Unlock()
	_, err = fmt.Fprintf(s.outWriter, "%s\n", string(data))
	return err
}

func (s *CoreWorkerServer) evaluateNativeTrust(ctx context.Context, reqID string, host string, peerCertsDER [][]byte) (*NativeTrustResult, error) {
	respCh := make(chan *NativeTrustResult, 1)
	s.trustLock.Lock()
	s.pendingTrust[reqID] = respCh
	s.trustLock.Unlock()

	defer func() {
		s.trustLock.Lock()
		delete(s.pendingTrust, reqID)
		s.trustLock.Unlock()
	}()

	var b64Chain []string
	for _, der := range peerCertsDER {
		b64Chain = append(b64Chain, base64.StdEncoding.EncodeToString(der))
	}

	evalReq := &WorkerRPCMessage{
		RequestID:      reqID,
		Method:         "native_trust.evaluate",
		Host:           host,
		DERChainBase64: b64Chain,
	}

	if err := s.writeMessage(evalReq); err != nil {
		return nil, fmt.Errorf("send native trust eval req: %w", err)
	}

	select {
	case res := <-respCh:
		if res == nil {
			return nil, errors.New("empty native trust response")
		}
		return res, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(4000 * time.Millisecond):
		return nil, errors.New("native trust evaluate timed out after 4.0s")
	}
}

func (s *CoreWorkerServer) handleProbeStart(msg *WorkerRPCMessage) {
	s.workerPoolSem <- struct{}{}
	go func() {
		defer func() { <-s.workerPoolSem }()

		deadlineMs := msg.DeadlineMs
		if deadlineMs <= 0 {
			deadlineMs = 8000
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadlineMs)*time.Millisecond)
		defer cancel()

		conn, targetIP, dialErr := DialTargetIPv4(ctx, msg.Host, msg.Port, msg.Route, msg.ProxyEndpoint, msg.AllowPrivate)
		if dialErr != nil {
			resp := &WorkerRPCMessage{
				RequestID: msg.RequestID,
				Method:    "probe.result",
				Outcome: &ProbeOutcome{
					TargetHost:         msg.Host,
					TargetPort:         msg.Port,
					RemoteIP:           targetIP.String(),
					RouteType:          msg.Route,
					ProxyEndpoint:      msg.ProxyEndpoint,
					HandshakeCompleted: false,
					DurationMs:         0,
					ErrorCode:          "DIAL_FAILED",
					ErrorMessage:       dialErr.Error(),
				},
				ErrorCode:    "DIAL_FAILED",
				ErrorMessage: dialErr.Error(),
			}
			_ = s.writeMessage(resp)
			return
		}

		nativeEvaluator := func(evalCtx context.Context, h string, ders [][]byte) (*NativeTrustResult, error) {
			return s.evaluateNativeTrust(evalCtx, msg.RequestID, h, ders)
		}

		remoteIPStr := ""
		if targetIP != nil {
			remoteIPStr = targetIP.String()
		} else if conn != nil {
			if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				remoteIPStr = tcpAddr.IP.String()
			}
		}

		outcome, _ := ProbeTLS(ctx, conn, msg.Host, msg.Port, msg.Route, msg.ProxyEndpoint, remoteIPStr, nativeEvaluator)

		resp := &WorkerRPCMessage{
			RequestID: msg.RequestID,
			Method:    "probe.result",
			Outcome:   outcome,
		}
		if outcome != nil && !outcome.HandshakeCompleted {
			resp.ErrorCode = outcome.ErrorCode
			resp.ErrorMessage = outcome.ErrorMessage
		}
		_ = s.writeMessage(resp)
	}()
}

func (s *CoreWorkerServer) handleNativeTrustResponse(msg *WorkerRPCMessage) {
	s.trustLock.Lock()
	ch, ok := s.pendingTrust[msg.RequestID]
	s.trustLock.Unlock()

	if ok && ch != nil {
		res := msg.NativeResult
		if res == nil {
			res = &NativeTrustResult{
				Accepted:           msg.Accepted,
				Errors:             msg.Errors,
				IsExtraTrustAnchor: msg.IsExtraTrustAnchor,
				ExtraAnchorSubject: msg.ExtraAnchorSubject,
			}
		} else {
			if msg.IsExtraTrustAnchor {
				res.IsExtraTrustAnchor = true
			}
			if msg.ExtraAnchorSubject != "" {
				res.ExtraAnchorSubject = msg.ExtraAnchorSubject
			}
		}
		ch <- res
	}
}

func (s *CoreWorkerServer) Run() error {
	for {
		line, err := s.inReader.ReadBytes('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(line) == 0 || (len(line) == 1 && line[0] == '\n') {
			continue
		}

		var msg WorkerRPCMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			_ = s.writeMessage(&WorkerRPCMessage{
				Method:       "error",
				ErrorCode:    "INVALID_JSON",
				ErrorMessage: err.Error(),
			})
			continue
		}

		switch msg.Method {
		case "probe.start":
			s.handleProbeStart(&msg)
		case "native_trust.response":
			s.handleNativeTrustResponse(&msg)
		case "ping":
			_ = s.writeMessage(&WorkerRPCMessage{
				RequestID: msg.RequestID,
				Method:    "pong",
			})
		default:
			_ = s.writeMessage(&WorkerRPCMessage{
				RequestID:    msg.RequestID,
				Method:       "error",
				ErrorCode:    "UNKNOWN_METHOD",
				ErrorMessage: fmt.Sprintf("unknown method: %s", msg.Method),
			})
		}
	}
}

func RunWorkerStdio() error {
	server := NewCoreWorkerServer(os.Stdin, os.Stdout, 4)
	return server.Run()
}
