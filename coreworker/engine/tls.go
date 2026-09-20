package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"time"
)

var (
	ErrNativeTrustRejected        = errors.New("NATIVE_TRUST_REJECTED: macOS SecTrust verification rejected the certificate chain")
	ErrNativeVerifierUnavailable  = errors.New("NATIVE_VERIFIER_UNAVAILABLE: native trust evaluator is unavailable or timed out")
	ErrCertChainTooLong           = errors.New("SECURITY_LIMIT_EXCEEDED: peer certificate chain exceeds 16 certificates")
	ErrCertSizeTooLarge           = errors.New("SECURITY_LIMIT_EXCEEDED: certificate size exceeds 64 KiB limit")
	ErrTotalCertChainSizeTooLarge = errors.New("SECURITY_LIMIT_EXCEEDED: total certificate chain size exceeds 256 KiB limit")
)

type NativeTrustResult struct {
	Accepted             bool     `json:"accepted"`
	Errors               []string `json:"errors,omitempty"`
	EvaluatedChainIDs    []string `json:"evaluated_chain_ids,omitempty"`
	TrustSnapshotID      string   `json:"trust_snapshot_id,omitempty"`
	IsExtraTrustAnchor   bool     `json:"is_extra_trust_anchor,omitempty"`
	ExtraAnchorSubject   string   `json:"extra_anchor_subject,omitempty"`
	ExtraAnchorSPKI      string   `json:"extra_anchor_spki,omitempty"`
}

type NativeTrustEvaluatorFunc func(ctx context.Context, host string, peerCertsDER [][]byte) (*NativeTrustResult, error)

type CertInfo struct {
	CertID             string   `json:"cert_id"`
	SPKIID             string   `json:"spki_id"`
	Subject            string   `json:"subject"`
	Issuer             string   `json:"issuer"`
	NotBeforeMs        int64    `json:"not_before_ms"`
	NotAfterMs         int64    `json:"not_after_ms"`
	IsCA               bool     `json:"is_ca"`
	KeyUsage           []string `json:"key_usage"`
	SignatureAlgorithm string   `json:"signature_algorithm"`
	DERBase64          string   `json:"der_base64"`
	DNSNames           []string `json:"dns_names"`
}

type ProbeOutcome struct {
	TargetHost          string                  `json:"target_host"`
	TargetPort          int                     `json:"target_port"`
	RemoteIP            string                  `json:"remote_ip"`
	RouteType           string                  `json:"route_type"`
	ProxyEndpoint       string                  `json:"proxy_endpoint,omitempty"`
	PresentedCerts      []*CertInfo             `json:"presented_certs"`
	PresentedChainIDs   []string                `json:"presented_chain_ids"`
	NativeTrustResult   *NativeTrustResult      `json:"native_trust_result,omitempty"`
	PublicPKIXResult    *PKIXVerificationResult `json:"public_pkix_result,omitempty"`
	HandshakeCompleted  bool                    `json:"handshake_completed"`
	TLSVersion          string                  `json:"tls_version"`
	NegotiatedProtocol  string                  `json:"negotiated_protocol"`
	DurationMs          int64                   `json:"duration_ms"`
	ErrorCode           string                  `json:"error_code,omitempty"`
	ErrorMessage        string                  `json:"error_message,omitempty"`
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

// ProbeTLS executes the TLS handshake against conn, applying the dual verification and limits.
func ProbeTLS(ctx context.Context, conn net.Conn, host string, port int, routeType string, proxyEndpoint string, remoteIP string, nativeEvaluator NativeTrustEvaluatorFunc) (*ProbeOutcome, error) {
	start := time.Now()
	defer conn.Close()

	outcome := &ProbeOutcome{
		TargetHost:    host,
		TargetPort:    port,
		RemoteIP:      remoteIP,
		RouteType:     routeType,
		ProxyEndpoint: proxyEndpoint,
	}

	var capturedPeerCerts []*x509.Certificate
	var nativeEvalResult *NativeTrustResult

	tlsConfig := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // FAIL-CLOSED: ONLY with VerifyConnection below!
		ClientSessionCache: nil,  // Disable session cache to force full certificate delivery
		NextProtos:         []string{"h2", "http/1.1"},
		VerifyConnection: func(cs tls.ConnectionState) error {
			peerCerts := cs.PeerCertificates
			if len(peerCerts) == 0 {
				return errors.New("no peer certificates presented")
			}

			// Security limits
			if len(peerCerts) > 16 {
				return ErrCertChainTooLong
			}

			var totalSize int
			var rawDERs [][]byte
			for _, cert := range peerCerts {
				size := len(cert.Raw)
				if size > 64*1024 {
					return ErrCertSizeTooLarge
				}
				totalSize += size
				rawDERs = append(rawDERs, cert.Raw)
			}
			if totalSize > 256*1024 {
				return ErrTotalCertChainSizeTooLarge
			}

			capturedPeerCerts = peerCerts

			// Invoke native macOS SecTrust verification
			if nativeEvaluator == nil {
				return ErrNativeVerifierUnavailable
			}
			evalCtx, cancel := context.WithTimeout(ctx, 4000*time.Millisecond)
			defer cancel()

			res, err := nativeEvaluator(evalCtx, host, rawDERs)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrNativeVerifierUnavailable, err)
			}
			nativeEvalResult = res
			if !res.Accepted {
				return ErrNativeTrustRejected
			}
			return nil
		},
	}

	tlsConn := tls.Client(conn, tlsConfig)
	handshakeErr := tlsConn.HandshakeContext(ctx)
	outcome.DurationMs = time.Since(start).Milliseconds()

	// Process presented certificates if available
	if len(capturedPeerCerts) > 0 {
		var presentedInfo []*CertInfo
		var presentedIDs []string

		for _, cert := range capturedPeerCerts {
			cID, spkiID := CertFingerprints(cert)
			presentedIDs = append(presentedIDs, cID)

			var keyUsages []string
			if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
				keyUsages = append(keyUsages, "digitalSignature")
			}
			if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
				keyUsages = append(keyUsages, "keyEncipherment")
			}
			if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
				keyUsages = append(keyUsages, "keyCertSign")
			}

			presentedInfo = append(presentedInfo, &CertInfo{
				CertID:             cID,
				SPKIID:             spkiID,
				Subject:            cert.Subject.String(),
				Issuer:             cert.Issuer.String(),
				NotBeforeMs:        cert.NotBefore.UnixMilli(),
				NotAfterMs:         cert.NotAfter.UnixMilli(),
				IsCA:               cert.IsCA,
				KeyUsage:           keyUsages,
				SignatureAlgorithm: cert.SignatureAlgorithm.String(),
				DERBase64:          base64.StdEncoding.EncodeToString(cert.Raw),
				DNSNames:           cert.DNSNames,
			})
		}
		outcome.PresentedCerts = presentedInfo
		outcome.PresentedChainIDs = presentedIDs
		outcome.NativeTrustResult = nativeEvalResult

		// Independent Go PKIX baseline validation
		outcome.PublicPKIXResult = ValidatePublicPKIX(host, capturedPeerCerts)
	}

	if handshakeErr != nil {
		outcome.HandshakeCompleted = false
		outcome.ErrorMessage = handshakeErr.Error()
		if errors.Is(handshakeErr, ErrNativeTrustRejected) {
			outcome.ErrorCode = "NATIVE_TRUST_REJECTED"
		} else if errors.Is(handshakeErr, ErrNativeVerifierUnavailable) {
			outcome.ErrorCode = "NATIVE_VERIFIER_UNAVAILABLE"
		} else if errors.Is(handshakeErr, context.DeadlineExceeded) {
			outcome.ErrorCode = "HANDSHAKE_TIMEOUT"
		} else {
			outcome.ErrorCode = "TLS_HANDSHAKE_FAILED"
		}
		return outcome, handshakeErr
	}

	outcome.HandshakeCompleted = true
	state := tlsConn.ConnectionState()
	outcome.TLSVersion = tlsVersionToString(state.Version)
	outcome.NegotiatedProtocol = state.NegotiatedProtocol
	return outcome, nil
}
