package jws

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
)

// JWS (JSON Web Signature) represents content secured with digital signatures or Message Authentication Codes (MACs) using JSON-based data structures.
// https://datatracker.ietf.org/doc/html/rfc7515
type JWS struct {
	Header       JWSDecodedHeader
	Payload      []byte
	Signature    []byte
	SigningInput []byte
}

type JWSDecodedHeader struct {
	Alg string   `json:"alg"`
	X5C []string `json:"x5c"`
}

func (s JWS) MarshalText() ([]byte, error) {
	encoding := base64.RawURLEncoding

	headerBytes, err := json.Marshal(s.Header)
	if err != nil {
		return nil, err
	}

	nheader := encoding.EncodedLen(len(headerBytes))
	npayload := encoding.EncodedLen(len(s.Payload))
	nsignature := encoding.EncodedLen(len(s.Signature))

	b := make([]byte, nheader+1+npayload+1+nsignature)

	encoding.Encode(b[0:nheader], headerBytes)
	b[nheader] = '.'
	encoding.Encode(b[nheader+1:nheader+1+npayload], s.Payload)
	b[nheader+1+npayload] = '.'
	encoding.Encode(b[nheader+1+npayload+1:], s.Signature)

	return b, nil
}

func (s *JWS) UnmarshalText(text []byte) error {
	parts := bytes.Split(text, []byte("."))
	if len(parts) != 3 {
		return errors.New("wrong number of parts")
	}

	s.SigningInput = text[:len(parts[0])+1+len(parts[1])]

	encoding := base64.RawURLEncoding

	headerBytes := make([]byte, encoding.DecodedLen(len(parts[0])))
	n, err := encoding.Decode(headerBytes, parts[0])
	if err != nil || n == 0 {
		return fmt.Errorf("bad header: base64 url decode header: %w", err)
	}
	headerBytes = headerBytes[:n]

	if err := json.Unmarshal(headerBytes, &s.Header); err != nil {
		return fmt.Errorf("bad header: json: %w", err)
	}

	s.Payload = make([]byte, encoding.DecodedLen(len(parts[1])))
	n, err = encoding.Decode(s.Payload, parts[1])
	if err != nil || n == 0 {
		return fmt.Errorf("bad payload: base64 url decode: %w", err)
	}
	s.Payload = s.Payload[:n]

	s.Signature = make([]byte, encoding.DecodedLen(len(parts[2])))
	n, err = encoding.Decode(s.Signature, parts[2])
	if err != nil || n == 0 {
		return fmt.Errorf("bad signature: base64 url decode: %w", err)
	}
	s.Signature = s.Signature[:n]

	return nil
}

type JWSVerifier struct {
	Roots            *x509.CertPool
	CertOCSPVerifier interface {
		VerifyCertOCSPStatus(ctx context.Context, cert, issuer *x509.Certificate) error
	}
}

// VerifyJWS verifies the JWS signature and certificate chain, including revocation status.
func (s JWSVerifier) VerifyJWS(ctx context.Context, jws JWS) (err error) {
	if len(jws.Header.X5C) == 0 {
		return errors.New("bad x5c: requires at least 1 certificate")
	}

	certs := make([]*x509.Certificate, 0, len(jws.Header.X5C))
	for _, b := range jws.Header.X5C {
		der, err := base64.StdEncoding.DecodeString(b)
		if err != nil {
			return fmt.Errorf("bad x5c: base64: %w", err)
		}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("bad x5c: x509: %w", err)
		}

		certs = append(certs, cert)
	}

	leaf := certs[0]

	opts := x509.VerifyOptions{
		Roots: s.Roots,
	}

	if len(certs) > 1 {
		opts.Intermediates = x509.NewCertPool()
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
	}

	chains, err := leaf.Verify(opts)
	if err != nil {
		return fmt.Errorf("cannot verify leaf: %w", err)
	}

	if c := s.CertOCSPVerifier; c != nil {
		for _, chain := range chains {
			for i, certInChain := range chain {
				if i == len(chain)-1 {
					continue
				}

				if err := c.VerifyCertOCSPStatus(ctx, certInChain, chain[i+1]); err != nil {
					return fmt.Errorf("bad certificate(%d): ocsp: %w", i, err)
				}
			}
		}
	}

	if jws.Header.Alg == "" || jws.Header.Alg == "none" {
		return errors.New("bad alg: none")
	}

	switch jws.Header.Alg {
	case "RS256":
		hf := crypto.SHA256
		h := hf.New()
		h.Write(jws.SigningInput)
		hashed := h.Sum(nil)

		pub, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("public key is not RSA")
		}

		if err := rsa.VerifyPKCS1v15(pub, hf, hashed, jws.Signature); err != nil {
			return fmt.Errorf("bad signature: cannot verify: %w", err)
		}
	case "RS512":
		hf := crypto.SHA512
		h := hf.New()
		h.Write(jws.SigningInput)
		hashed := h.Sum(nil)

		pub, ok := leaf.PublicKey.(*rsa.PublicKey)
		if !ok {
			return errors.New("public key is not RSA")
		}

		if err := rsa.VerifyPKCS1v15(pub, hf, hashed, jws.Signature); err != nil {
			return fmt.Errorf("bad signature: cannot verify: %w", err)
		}
	case "ES256":
		hashFunc := crypto.SHA256
		h := hashFunc.New()
		h.Write(jws.SigningInput)
		hashed := h.Sum(nil)

		pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("public key is not ECDSA")
		}
		if pub.Curve != elliptic.P256() {
			return errors.New("ECDSA curve is not P-256 for ES256")
		}

		if len(jws.Signature) != 64 {
			return errors.New("invalid signature length for ES256")
		}

		rVal := new(big.Int).SetBytes(jws.Signature[:32])
		sVal := new(big.Int).SetBytes(jws.Signature[32:])
		if !ecdsa.Verify(pub, hashed, rVal, sVal) {
			return errors.New("bad signature: cannot verify")
		}
	default:
		return fmt.Errorf("bad alg: %s: not supported", jws.Header.Alg)
	}

	return nil
}
