package crypto

import (
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Role designates the message sender in nonce derivation.
type Role byte

const (
	// RoleInitiator represents frames sent by the initiator (0x00).
	RoleInitiator Role = 0x00
	// RoleJoiner represents frames sent by the joiner (0x01).
	RoleJoiner Role = 0x01
)

const (
	// KDFInfo is the HKDF-SHA256 info string defined in PROTOCOL.md.
	KDFInfo = "psych-v1-session-key"
	// KeySize is the size of the derived symmetric key in bytes (32).
	KeySize = 32
	// NonceSize is the size of the ChaCha20-Poly1305 nonce in bytes (12).
	NonceSize = 12
	// SessionIDRawBytes is the number of random bytes for the session ID (16).
	SessionIDRawBytes = 16
)

var (
	ErrInvalidNonceLength   = errors.New("nonce must be 12 bytes")
	ErrInvalidNonceRole     = errors.New("invalid nonce role")
	ErrInvalidNonceReserved = errors.New("nonce reserved bytes must be zero")
	ErrNonceSeqReplay       = errors.New("nonce sequence number already seen or out of order")
	ErrTamperedCiphertext   = errors.New("ciphertext authentication failed (tampered or corrupted)")
)

// GenerateKeyPair generates an ephemeral X25519 private/public keypair.
func GenerateKeyPair() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

// KeyPairFromPrivateBytes reconstructs an X25519 private key from 32 raw bytes.
func KeyPairFromPrivateBytes(privBytes []byte) (*ecdh.PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(privBytes)
}

// ComputeSharedSecret performs X25519 ECDH between local private key and remote public key.
func ComputeSharedSecret(priv *ecdh.PrivateKey, peerPubBytes []byte) ([]byte, error) {
	if len(peerPubBytes) != 32 {
		return nil, fmt.Errorf("invalid peer public key length: expected 32 bytes, got %d", len(peerPubBytes))
	}
	remotePub, err := ecdh.X25519().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse peer public key: %w", err)
	}
	sharedSecret, err := priv.ECDH(remotePub)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}
	return sharedSecret, nil
}

// DeriveSessionKey derives the 32-byte symmetric key K using HKDF-SHA256.
// Salt is empty string / zero-length byte array, info is "psych-v1-session-key".
func DeriveSessionKey(sharedSecret []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(KDFInfo))
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	return key, nil
}

// NewAEAD creates a ChaCha20-Poly1305 AEAD cipher using the derived 32-byte key.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", KeySize, len(key))
	}
	return chacha20poly1305.New(key)
}

// Encrypt encrypts and authenticates plaintext using ChaCha20-Poly1305 with the provided 12-byte nonce.
func Encrypt(aead cipher.AEAD, nonce []byte, plaintext []byte) []byte {
	return aead.Seal(nil, nonce, plaintext, nil)
}

// Decrypt authenticates and decrypts ciphertext using ChaCha20-Poly1305 with the provided 12-byte nonce.
func Decrypt(aead cipher.AEAD, nonce []byte, ciphertext []byte) ([]byte, error) {
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, ErrTamperedCiphertext
	}
	return plaintext, nil
}

// BuildNonce constructs a 12-byte nonce per PROTOCOL.md:
// - Byte 0: Role (0x00 Initiator, 0x01 Joiner)
// - Bytes 1-3: Reserved (0x00, 0x00, 0x00)
// - Bytes 4-11: Big-endian unsigned 64-bit integer counter.
func BuildNonce(role Role, seq uint64) []byte {
	nonce := make([]byte, NonceSize)
	nonce[0] = byte(role)
	// bytes 1..3 remain 0x00
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

// ParseNonce decomposes a 12-byte nonce into its role and sequence number.
func ParseNonce(nonce []byte) (Role, uint64, error) {
	if len(nonce) != NonceSize {
		return 0, 0, ErrInvalidNonceLength
	}
	role := Role(nonce[0])
	if role != RoleInitiator && role != RoleJoiner {
		return 0, 0, ErrInvalidNonceRole
	}
	if nonce[1] != 0 || nonce[2] != 0 || nonce[3] != 0 {
		return 0, 0, ErrInvalidNonceReserved
	}
	seq := binary.BigEndian.Uint64(nonce[4:12])
	return role, seq, nil
}

// NonceCounter provides thread-safe, monotonic generation of sequential nonces for a given role.
type NonceCounter struct {
	mu      sync.Mutex
	role    Role
	counter uint64
}

// NewNonceCounter initializes a new NonceCounter for a specified role.
func NewNonceCounter(role Role) *NonceCounter {
	return &NonceCounter{
		role:    role,
		counter: 0,
	}
}

// Next returns the current sequence number and its corresponding 12-byte nonce,
// incrementing the internal counter by 1.
func (nc *NonceCounter) Next() (uint64, []byte) {
	nc.mu.Lock()
	defer nc.mu.Unlock()

	seq := nc.counter
	nonce := BuildNonce(nc.role, seq)
	nc.counter++
	return seq, nonce
}

// NonceValidator validates incoming nonces from a peer.
type NonceValidator struct {
	mu           sync.Mutex
	expectedRole Role
	lastSeq      uint64
	initialized  bool
}

// NewNonceValidator creates a validator expecting frames from the specified role.
func NewNonceValidator(expectedRole Role) *NonceValidator {
	return &NonceValidator{
		expectedRole: expectedRole,
	}
}

// Validate checks that the nonce matches the expected role, zeroed reserved bytes,
// and strictly increases monotonically to protect against replay attacks.
func (nv *NonceValidator) Validate(nonce []byte, seq uint64) error {
	nv.mu.Lock()
	defer nv.mu.Unlock()

	role, nonceSeq, err := ParseNonce(nonce)
	if err != nil {
		return err
	}
	if role != nv.expectedRole {
		return fmt.Errorf("%w: expected 0x%02x, got 0x%02x", ErrInvalidNonceRole, nv.expectedRole, role)
	}
	if nonceSeq != seq {
		return fmt.Errorf("nonce sequence mismatch: envelope seq=%d, nonce seq=%d", seq, nonceSeq)
	}
	if nv.initialized && seq <= nv.lastSeq {
		return fmt.Errorf("%w: received seq %d <= last seq %d", ErrNonceSeqReplay, seq, nv.lastSeq)
	}
	nv.lastSeq = seq
	nv.initialized = true
	return nil
}

// GenerateSessionID generates a cryptographically secure 16-byte random session ID (32 hex characters).
func GenerateSessionID() (string, error) {
	b := make([]byte, SessionIDRawBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate random session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
