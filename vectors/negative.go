package vectors

import (
	"crypto"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/aurora-protocol/aurora-core/admission"
	auroracrypto "github.com/aurora-protocol/aurora-core/crypto"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type NegativeVectorCase struct {
	Name     string
	Rejected bool
	Error    string
	Evidence string
}

type NegativeVectorReport struct {
	Passed   bool
	Cases    []NegativeVectorCase
	Findings []string
}

func GenerateNegativeVectorReport() (NegativeVectorReport, error) {
	report := NegativeVectorReport{Passed: true}

	if err := addMalformedPublicKeyCase(&report); err != nil {
		return NegativeVectorReport{}, err
	}
	if err := addWrongKeyEncodingCase(&report); err != nil {
		return NegativeVectorReport{}, err
	}
	if err := addWrongSignatureCase(&report); err != nil {
		return NegativeVectorReport{}, err
	}
	if err := addWrongAEADTagCase(&report); err != nil {
		return NegativeVectorReport{}, err
	}
	if err := addReplayCase(&report); err != nil {
		return NegativeVectorReport{}, err
	}
	if err := addWrongTokenCase(&report); err != nil {
		return NegativeVectorReport{}, err
	}
	return report, nil
}

func (r *NegativeVectorReport) addCase(name string, rejected bool, rejection error, evidence string) {
	errText := ""
	if rejection != nil {
		errText = rejection.Error()
	}
	r.Cases = append(r.Cases, NegativeVectorCase{
		Name:     name,
		Rejected: rejected,
		Error:    errText,
		Evidence: evidence,
	})
	if !rejected {
		r.Passed = false
		r.Findings = append(r.Findings, name+" negative vector was accepted")
	}
}

func addMalformedPublicKeyCase(report *NegativeVectorReport) error {
	malformed := append([]byte{0x04}, repeated(0x00, 64)...)
	err := auroracrypto.VerifySignature(
		registry.SigECDSAP256SHA384DER,
		registry.KeyP256SEC1Uncompressed,
		malformed,
		repeated(0x41, 48),
		[]byte{0x30, 0x00},
	)
	report.addCase(
		"malformed_public_key",
		err != nil,
		err,
		"scheme=ecdsa_p256_sha384_der key_encoding=p256_sec1_uncompressed public_key="+hex.EncodeToString(malformed),
	)
	return nil
}

func addWrongKeyEncodingCase(report *NegativeVectorReport) error {
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], repeated(0x51, len(seed)))
	publicKey, _ := mldsa65.NewKeyFromSeed(&seed)
	err := auroracrypto.VerifySignature(
		registry.SigMLDSA65,
		registry.KeyP256SEC1Uncompressed,
		publicKey.Bytes(),
		repeated(0x52, 48),
		repeated(0x53, mldsa65.SignatureSize),
	)
	report.addCase(
		"wrong_key_encoding",
		err != nil,
		err,
		"scheme=mldsa65 key_encoding=p256_sec1_uncompressed public_key_len="+fmt.Sprint(len(publicKey.Bytes())),
	)
	return nil
}

func addWrongSignatureCase(report *NegativeVectorReport) error {
	signer, err := ecdsaPrivateKeyFromScalar(repeated(0x61, 32))
	if err != nil {
		return err
	}
	publicKey, err := signer.PublicKey.Bytes()
	if err != nil {
		return err
	}
	message := repeated(0x62, 48)
	signature, err := signer.Sign(nil, message, crypto.SHA384)
	if err != nil {
		return err
	}
	tampered := append([]byte(nil), signature...)
	tampered[len(tampered)-1] ^= 0x01
	if err := auroracrypto.VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SEC1Uncompressed, publicKey, message, signature); err != nil {
		return err
	}
	err = auroracrypto.VerifySignature(registry.SigECDSAP256SHA384DER, registry.KeyP256SEC1Uncompressed, publicKey, message, tampered)
	report.addCase(
		"wrong_signature",
		err != nil,
		err,
		"scheme=ecdsa_p256_sha384_der signature="+hex.EncodeToString(tampered),
	)
	return nil
}

func addWrongAEADTagCase(report *NegativeVectorReport) error {
	key := repeated(0x71, 32)
	nonce := repeated(0x72, 12)
	aad := []byte("negative-vector-aad")
	plaintext := []byte("negative-vector-plaintext")
	sealed, err := auroracrypto.AES256GCMSeal(key, nonce, aad, plaintext)
	if err != nil {
		return err
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	_, err = auroracrypto.AES256GCMOpen(key, nonce, aad, tampered)
	report.addCase(
		"wrong_aead_tag",
		err != nil,
		err,
		"ciphertext_tag="+hex.EncodeToString(tampered),
	)
	return nil
}

func addReplayCase(report *NegativeVectorReport) error {
	cache := admission.NewMemoryReplayCache()
	key := repeated(0x81, 32)
	first, err := cache.InsertIfAbsent(key)
	if err != nil {
		return err
	}
	second, err := cache.InsertIfAbsent(key)
	if err != nil {
		return err
	}
	rejected := first && !second
	var rejection error
	if rejected {
		rejection = fmt.Errorf("admission: replay key already spent")
	}
	report.addCase(
		"replay",
		rejected,
		rejection,
		"replay_key="+hex.EncodeToString(key),
	)
	return nil
}

// addWrongTokenCase issues a real Blind RSA admission proof, tampers its token
// authenticator, and confirms the relay-side verifier fails closed — the P11
// "wrong-token ... fail closed" release gate.
func addWrongTokenCase(report *NegativeVectorReport) error {
	service, err := issuerd.NewHarnessService(200)
	if err != nil {
		return err
	}
	proof, err := service.IssueBlindRSA2048(issuerd.IssueBlindRSA2048Request{
		TokenNonce:            repeated(0x44, 32),
		RedemptionContextHash: repeated(0x45, 48),
		ExpiryUnix:            300,
	})
	if err != nil {
		return err
	}
	metadata := service.PublishIssuerMetadata()
	if vErr := admission.VerifyBlindRSA2048WithIssuerMetadata(proof, metadata, 250); vErr != nil {
		return fmt.Errorf("vectors: baseline blind-rsa proof did not verify: %w", vErr)
	}
	if len(proof.TokenAuthenticator) == 0 {
		return fmt.Errorf("vectors: issued proof has empty token authenticator")
	}
	tampered := proof
	tampered.TokenAuthenticator = append([]byte(nil), proof.TokenAuthenticator...)
	tampered.TokenAuthenticator[0] ^= 0xff
	verifyErr := admission.VerifyBlindRSA2048WithIssuerMetadata(tampered, metadata, 250)
	report.addCase(
		"wrong_token",
		verifyErr != nil,
		verifyErr,
		"proof_type=blind_rsa_2048 tamper=token_authenticator[0]^0xff",
	)
	return nil
}

func FormatNegativeVectorReport(report NegativeVectorReport) string {
	var b strings.Builder
	failures := len(report.Findings)
	fmt.Fprintf(&b, "negative_vectors_check passed=%t cases=%d failures=%d\n", report.Passed, len(report.Cases), failures)
	for _, c := range report.Cases {
		fmt.Fprintf(&b, "negative_vector %s rejected=%t error=%q evidence=%s\n", c.Name, c.Rejected, c.Error, c.Evidence)
	}
	for _, finding := range report.Findings {
		fmt.Fprintf(&b, "negative_vector_finding %s\n", finding)
	}
	return b.String()
}
