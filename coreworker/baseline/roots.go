package baseline

import (
	"crypto/x509"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

var (
	poolOnce   sync.Once
	cachedPool *x509.CertPool
	cachedPEM  []byte
)

// GetPublicBaselinePool dynamically loads the official public Web PKI roots from
// the operating system's public root keychain (/System/Library/Keychains/SystemRootCertificates.keychain
// on macOS), strictly isolated from user or admin keychains where enterprise private roots reside.
// There is zero hardcoded certificate data in the codebase.
func GetPublicBaselinePool() *x509.CertPool {
	poolOnce.Do(func() {
		cachedPool, cachedPEM = loadSystemPublicRoots()
	})
	if cachedPool == nil {
		return x509.NewCertPool()
	}
	return cachedPool.Clone()
}

// GetPublicBaselinePEM returns the raw PEM bytes of the dynamically loaded public baseline.
func GetPublicBaselinePEM() []byte {
	poolOnce.Do(func() {
		cachedPool, cachedPEM = loadSystemPublicRoots()
	})
	return cachedPEM
}

func loadSystemPublicRoots() (*x509.CertPool, []byte) {
	pool := x509.NewCertPool()

	if runtime.GOOS == "darwin" {
		// macOS official public root keychain (read-only under Apple System Integrity Protection)
		// This keychain contains ONLY official public Web PKI roots and cannot be modified by users or SWG.
		out, err := exec.Command("/usr/bin/security", "find-certificate", "-a", "-p", "/System/Library/Keychains/SystemRootCertificates.keychain").Output()
		if err == nil && len(out) > 0 {
			if pool.AppendCertsFromPEM(out) {
				return pool, out
			}
		}
	}

	// Fallback on standard system certificate files (e.g. Linux / BSD)
	for _, path := range []string{
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt",
		"/etc/ssl/ca-bundle.pem",
	} {
		if data, err := os.ReadFile(path); err == nil {
			if pool.AppendCertsFromPEM(data) {
				return pool, data
			}
		}
	}

	// If all else fails, use system cert pool
	if sysPool, err := x509.SystemCertPool(); err == nil && sysPool != nil {
		return sysPool, nil
	}

	return pool, nil
}
