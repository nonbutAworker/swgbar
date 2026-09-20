package engine

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"swgbar/coreworker/baseline"
)

type PKIXVerificationResult struct {
	Passed        bool       `json:"passed"`
	ErrorCode     string     `json:"error_code,omitempty"`
	ErrorMessage  string     `json:"error_message,omitempty"`
	VerifiedPaths [][]string `json:"verified_paths,omitempty"` // SHA256 of DER in chain
}

// CertFingerprints computes SHA256(DER) and SHA256(SubjectPublicKeyInfo)
func CertFingerprints(cert *x509.Certificate) (certID string, spkiID string) {
	derSum := sha256.Sum256(cert.Raw)
	certID = hex.EncodeToString(derSum[:])

	spkiSum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	spkiID = hex.EncodeToString(spkiSum[:])
	return certID, spkiID
}

// ValidatePublicPKIX verifies peer certs against the hardcoded public root baseline.
// It creates a strict x509.NewCertPool() and does NOT read the system certificate pool.
func ValidatePublicPKIX(host string, certs []*x509.Certificate) *PKIXVerificationResult {
	if len(certs) == 0 {
		return &PKIXVerificationResult{
			Passed:       false,
			ErrorCode:    "NO_CERTIFICATES",
			ErrorMessage: "peer did not present any certificates",
		}
	}

	// 1. Get dynamically loaded public baseline pool (from OS SystemRootCertificates, 0 hardcoding)
	rootPool := baseline.GetPublicBaselinePool()
	if rootPool == nil {
		return &PKIXVerificationResult{
			Passed:       false,
			ErrorCode:    "BASELINE_POOL_INIT_FAILED",
			ErrorMessage: "failed to initialize public baseline root pool",
		}
	}

	// 2. Build intermediate pool from presented certificates
	intermediatePool := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediatePool.AddCert(c)
	}

	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         rootPool,
		Intermediates: intermediatePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		var code string
		switch {
		case errors.As(err, &x509.HostnameError{}):
			code = "HOSTNAME_MISMATCH"
		case errors.As(err, &x509.CertificateInvalidError{}):
			code = "CERTIFICATE_INVALID"
		case errors.As(err, &x509.UnknownAuthorityError{}):
			code = "UNKNOWN_AUTHORITY"
		default:
			code = "PKIX_VERIFY_FAILED"
		}
		return &PKIXVerificationResult{
			Passed:       false,
			ErrorCode:    code,
			ErrorMessage: err.Error(),
		}
	}

	var verifiedPaths [][]string
	for _, chain := range chains {
		var path []string
		for _, cert := range chain {
			cID, _ := CertFingerprints(cert)
			path = append(path, cID)
		}
		verifiedPaths = append(verifiedPaths, path)
	}

	return &PKIXVerificationResult{
		Passed:        true,
		VerifiedPaths: verifiedPaths,
	}
}
