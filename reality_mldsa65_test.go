package tls

import (
	"bytes"
	"crypto/x509"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

func TestRealityMldsa65CertificateOffset(t *testing.T) {
	_, certificates := realityServerCert()
	if certificates.mldsa65Offset <= 0 {
		t.Fatalf("invalid offset %d", certificates.mldsa65Offset)
	}
	signedCert := append([]byte{}, certificates.signedCertMldsa65...)
	marker := bytes.Repeat([]byte{0x5a}, mldsa65.SignatureSize)
	copy(signedCert[certificates.mldsa65Offset:], marker)
	certificate, err := x509.ParseCertificate(signedCert)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.Extensions) == 0 || !bytes.Equal(certificate.Extensions[0].Value, marker) {
		t.Fatal("signature is not placed in the first certificate extension")
	}
	// Xray's REALITY writes the signature at a fixed location.
	if certificates.mldsa65Offset != 126 {
		t.Fatalf("offset %d differs from Xray's fixed location 126", certificates.mldsa65Offset)
	}
}
