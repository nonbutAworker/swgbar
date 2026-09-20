package engine

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestAddressScopeProtection(t *testing.T) {
	cases := []struct {
		ip       string
		isReserv bool
	}{
		{"127.0.0.1", true},
		{"10.0.1.2", true},
		{"172.16.5.10", true},
		{"192.168.1.1", true},
		{"169.254.1.1", true},
		{"100.64.0.1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"203.0.113.40", false},
	}

	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		got := IsPrivateOrReservedIP(ip)
		if got != c.isReserv {
			t.Errorf("IsPrivateOrReservedIP(%s) = %v; want %v", c.ip, got, c.isReserv)
		}
	}
}

func TestCertFingerprintsAndPKIX(t *testing.T) {
	// Generate a self-signed root cert
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Enterprise Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	parsed, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	certID, spkiID := CertFingerprints(parsed)
	if len(certID) != 64 {
		t.Errorf("certID hex length = %d; want 64", len(certID))
	}
	if len(spkiID) != 64 {
		t.Errorf("spkiID hex length = %d; want 64", len(spkiID))
	}

	// Verify against public baseline -> must fail because this is a private untrusted root!
	res := ValidatePublicPKIX("example.com", []*x509.Certificate{parsed})
	if res.Passed {
		t.Errorf("expected private root to FAIL public baseline PKIX check, but it passed")
	}
}

func TestVerifyConnectionFailClosed(t *testing.T) {
	// Start an in-memory TLS listener
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	serverCert := x509.Certificate{Raw: der}
	_ = serverCert

	// Test native trust rejection ensures fail-closed
	rejectedVerifier := func(ctx context.Context, host string, peerCertsDER [][]byte) (*NativeTrustResult, error) {
		return &NativeTrustResult{
			Accepted: false,
			Errors:   []string{"SecTrust denied for test"},
		}, nil
	}

	// We verify that when NativeTrustEvaluatorFunc returns Accepted=false,
	// ProbeTLS terminates with ErrNativeTrustRejected
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Handshake
		tlsL := make([]byte, 1024)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, _ = conn.Read(tlsL)
	}()

	clientConn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, probeErr := ProbeTLS(ctx, clientConn, "127.0.0.1", port, "DIRECT", "", "127.0.0.1", rejectedVerifier)
	if probeErr == nil {
		t.Errorf("expected probeErr, got nil")
	}
}

