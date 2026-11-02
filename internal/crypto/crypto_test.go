package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestECDHKnownVector tests X25519 key agreement using the RFC 7748 Section 6.1 test vector.
func TestECDHKnownVector(t *testing.T) {
	privHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	pubHex := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	peerPubHex := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	expectedSecretHex := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("decode priv: %v", err)
	}
	priv, err := KeyPairFromPrivateBytes(privBytes)
	if err != nil {
		t.Fatalf("load priv: %v", err)
	}

	calculatedPub := hex.EncodeToString(priv.PublicKey().Bytes())
	if calculatedPub != pubHex {
		t.Fatalf("pub mismatch: got %s, want %s", calculatedPub, pubHex)
	}

	peerPubBytes, err := hex.DecodeString(peerPubHex)
	if err != nil {
		t.Fatalf("decode peer pub: %v", err)
	}

	sharedSecret, err := ComputeSharedSecret(priv, peerPubBytes)
	if err != nil {
		t.Fatalf("compute shared secret: %v", err)
	}
	if hex.EncodeToString(sharedSecret) != expectedSecretHex {
		t.Fatalf("secret mismatch: got %s, want %s", hex.EncodeToString(sharedSecret), expectedSecretHex)
	}
}

// TestECDHMutualAgreement verifies mutual key agreement with randomly generated keypairs.
func TestECDHMutualAgreement(t *testing.T) {
	initiatorPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate initiator keypair: %v", err)
	}
	joinerPriv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate joiner keypair: %v", err)
	}

	initiatorPub := initiatorPriv.PublicKey().Bytes()
	joinerPub := joinerPriv.PublicKey().Bytes()

	secret1, err := ComputeSharedSecret(initiatorPriv, joinerPub)
	if err != nil {
		t.Fatalf("initiator compute secret: %v", err)
	}
	secret2, err := ComputeSharedSecret(joinerPriv, initiatorPub)
	if err != nil {
		t.Fatalf("joiner compute secret: %v", err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("shared secrets do not match between initiator and joiner")
	}

	// Verify derived symmetric key K is identical on both sides
	key1, err := DeriveSessionKey(secret1)
	if err != nil {
		t.Fatalf("derive key 1: %v", err)
	}
	key2, err := DeriveSessionKey(secret2)
	if err != nil {
		t.Fatalf("derive key 2: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatalf("derived keys do not match")
	}
	if len(key1) != 32 {
		t.Fatalf("derived key length is %d, expected 32", len(key1))
	}
}

// TestChaCha20Poly1305AndTampering verifies encryption, decryption, and authentication failures on tampering.
func TestChaCha20Poly1305AndTampering(t *testing.T) {
	priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	secret, err := ComputeSharedSecret(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeriveSessionKey(secret)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := NewAEAD(key)
	if err != nil {
		t.Fatalf("new AEAD: %v", err)
	}

	nonce := BuildNonce(RoleInitiator, 0)
	plaintext := []byte("Zero-knowledge end-to-end encrypted message")

	ciphertext := Encrypt(aead, nonce, plaintext)

	// Decrypt valid
	decrypted, err := Decrypt(aead, nonce, ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("plaintext mismatch: got %s, want %s", string(decrypted), string(plaintext))
	}

	// 1. Bit flip in ciphertext body
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[2] ^= 0x01
	if _, err := Decrypt(aead, nonce, tamperedCiphertext); err == nil {
		t.Fatal("expected decryption failure on tampered ciphertext body")
	}

	// 2. Bit flip in authentication tag (last 16 bytes)
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0x80
	if _, err := Decrypt(aead, nonce, tamperedCiphertext); err == nil {
		t.Fatal("expected decryption failure on tampered auth tag")
	}

	// 3. Truncated ciphertext
	truncated := ciphertext[:len(ciphertext)-5]
	if _, err := Decrypt(aead, nonce, truncated); err == nil {
		t.Fatal("expected decryption failure on truncated ciphertext")
	}

	// 4. Wrong nonce
	wrongNonce := BuildNonce(RoleJoiner, 0)
	if _, err := Decrypt(aead, wrongNonce, ciphertext); err == nil {
		t.Fatal("expected decryption failure on wrong nonce")
	}

	// 5. Wrong key
	wrongKey := make([]byte, 32)
	copy(wrongKey, key)
	wrongKey[0] ^= 0xFF
	wrongAEAD, _ := NewAEAD(wrongKey)
	if _, err := Decrypt(wrongAEAD, nonce, ciphertext); err == nil {
		t.Fatal("expected decryption failure on wrong key")
	}
}

// TestNonceMonotonicityAndDirection verifies directional prefix separation and sequence increments.
func TestNonceMonotonicityAndDirection(t *testing.T) {
	initCounter := NewNonceCounter(RoleInitiator)
	joinCounter := NewNonceCounter(RoleJoiner)

	initVal := NewNonceValidator(RoleInitiator)
	joinVal := NewNonceValidator(RoleJoiner)

	for i := uint64(0); i < 100; i++ {
		seqI, nonceI := initCounter.Next()
		if seqI != i {
			t.Fatalf("initiator counter mismatch: got %d, want %d", seqI, i)
		}
		if nonceI[0] != 0x00 {
			t.Fatalf("initiator nonce byte 0 must be 0x00, got 0x%02x", nonceI[0])
		}
		if nonceI[1] != 0 || nonceI[2] != 0 || nonceI[3] != 0 {
			t.Fatalf("initiator nonce reserved bytes not zero: %v", nonceI[1:4])
		}
		if err := initVal.Validate(nonceI, seqI); err != nil {
			t.Fatalf("initiator validation failed at seq %d: %v", i, err)
		}

		seqJ, nonceJ := joinCounter.Next()
		if seqJ != i {
			t.Fatalf("joiner counter mismatch: got %d, want %d", seqJ, i)
		}
		if nonceJ[0] != 0x01 {
			t.Fatalf("joiner nonce byte 0 must be 0x01, got 0x%02x", nonceJ[0])
		}
		if nonceJ[1] != 0 || nonceJ[2] != 0 || nonceJ[3] != 0 {
			t.Fatalf("joiner nonce reserved bytes not zero: %v", nonceJ[1:4])
		}
		if err := joinVal.Validate(nonceJ, seqJ); err != nil {
			t.Fatalf("joiner validation failed at seq %d: %v", i, err)
		}

		// Cross validation should fail (joiner nonce given to initiator validator)
		if err := initVal.Validate(nonceJ, seqJ); err == nil {
			t.Fatalf("expected error validating joiner nonce against initiator validator")
		}
	}

	// Replay validation failure
	oldNonce := BuildNonce(RoleInitiator, 50)
	if err := initVal.Validate(oldNonce, 50); err == nil {
		t.Fatal("expected replay attack failure for previously seen sequence number")
	}
}

// TestSessionIDGeneration tests length and hex format.
func TestSessionIDGeneration(t *testing.T) {
	sid, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("generate sid: %v", err)
	}
	if len(sid) != 32 {
		t.Fatalf("sid length is %d, expected 32 hex chars", len(sid))
	}
	raw, err := hex.DecodeString(sid)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("raw sid length is %d, expected 16 bytes", len(raw))
	}
}

// TestPairingCodeGenerationAndNormalization verifies code generation and normalization.
func TestPairingCodeGenerationAndNormalization(t *testing.T) {
	code, err := GeneratePairingCode()
	if err != nil {
		t.Fatalf("failed to generate pairing code: %v", err)
	}
	if len(code) != 9 || code[4] != '-' {
		t.Fatalf("unexpected code format: %q", code)
	}

	if !IsPairingCode(code) {
		t.Fatalf("expected code %q to be valid", code)
	}

	norm := NormalizePairingCode(code)
	if len(norm) != 8 {
		t.Fatalf("normalized code length: got %d, want 8", len(norm))
	}
	if !IsPairingCode(norm) {
		t.Fatalf("expected normalized code %q to be valid", norm)
	}

	// Test case-insensitivity and Crockford substitutions
	testCases := []struct {
		input    string
		expected string
		valid    bool
	}{
		{"7k4m-9p2x", "7K4M9P2X", true},
		{"7K4M9P2X", "7K4M9P2X", true},
		{"7k4m 9p2x", "7K4M9P2X", true},
		{"O1IL-9P2X", "01119P2X", true}, // O->0, I->1, L->1
		{"short", "", false},
		{"toolongcode123", "", false},
	}

	for _, tc := range testCases {
		if tc.valid {
			if !IsPairingCode(tc.input) {
				t.Errorf("expected %q to be recognized as valid code", tc.input)
			}
			got := NormalizePairingCode(tc.input)
			if got != tc.expected {
				t.Errorf("NormalizePairingCode(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		} else {
			if IsPairingCode(tc.input) {
				t.Errorf("expected %q to be recognized as invalid code", tc.input)
			}
		}
	}

	// Test deterministic SID derivation
	sid1 := DeriveSessionIDFromCode("7K4M-9P2X")
	sid2 := DeriveSessionIDFromCode("7k4m9p2x")
	if sid1 != sid2 {
		t.Fatalf("deterministic SIDs do not match: %s != %s", sid1, sid2)
	}
	if len(sid1) != 32 {
		t.Fatalf("derived SID length: got %d, want 32", len(sid1))
	}
}

// TestPAKEKeyDerivation verifies that both peers compute identical session keys with matching codes,
// and different keys with mismatched codes.
func TestPAKEKeyDerivation(t *testing.T) {
	code := "7K4M-9P2X"

	// 1. Joiner initializes PAKE
	joinerPake, joinerMsg, err := PAKEJoinerInit(code)
	if err != nil {
		t.Fatalf("PAKEJoinerInit failed: %v", err)
	}

	// 2. Initiator responds
	initiatorReply, initiatorKey, err := PAKEInitiatorRespond(code, joinerMsg)
	if err != nil {
		t.Fatalf("PAKEInitiatorRespond failed: %v", err)
	}

	// 3. Joiner finalizes
	joinerKey, err := PAKEJoinerFinalize(joinerPake, initiatorReply)
	if err != nil {
		t.Fatalf("PAKEJoinerFinalize failed: %v", err)
	}

	if !bytes.Equal(initiatorKey, joinerKey) {
		t.Fatalf("PAKE derived keys mismatch: initiator=%x joiner=%x", initiatorKey, joinerKey)
	}
	if len(initiatorKey) != 32 {
		t.Fatalf("PAKE key length: got %d, want 32", len(initiatorKey))
	}

	// 4. Test with mismatched code: keys must NOT match
	wrongCode := "W999-XXXX"
	_, wrongKey, err := PAKEInitiatorRespond(wrongCode, joinerMsg)
	if err == nil && bytes.Equal(wrongKey, joinerKey) {
		t.Fatal("expected different keys with mismatched code, but got identical keys")
	}
}
