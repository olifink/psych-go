package client

import (
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"psych/internal/crypto"
	"psych/internal/protocol"
)

var (
	ErrHandshakeFailed = errors.New("peer handshake failed")
	ErrSessionClosed   = errors.New("session closed")
)

// Client represents an authenticated, end-to-end encrypted peer connection.
type Client struct {
	conn            *websocket.Conn
	writeMu         sync.Mutex
	stateMu         sync.RWMutex
	privKey         *ecdh.PrivateKey
	pubKeyHex       string
	peerPubHex      string
	role            crypto.Role
	aead            cipher.AEAD
	counter         *crypto.NonceCounter
	validator       *crypto.NonceValidator
	sid             string
	code            string
	relayURL        string
	closed          chan struct{}
	onceClose       sync.Once
	OnPeerConnected func()
}

// ConnectInitiator connects to the relay as the initiator, waiting for a joiner to arrive and send a handshake.
func ConnectInitiator(relayURL string, sid string, privKey *ecdh.PrivateKey, code ...string) (*Client, error) {
	wsEndpoint, err := constructWSEndpoint(relayURL, sid)
	if err != nil {
		return nil, err
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}

	c := &Client{
		conn:      conn,
		privKey:   privKey,
		pubKeyHex: hex.EncodeToString(privKey.PublicKey().Bytes()),
		role:      crypto.RoleInitiator,
		sid:       sid,
		relayURL:  relayURL,
		counter:   crypto.NewNonceCounter(crypto.RoleInitiator),
		validator: crypto.NewNonceValidator(crypto.RoleJoiner),
		closed:    make(chan struct{}),
	}
	if len(code) > 0 {
		c.code = crypto.NormalizePairingCode(code[0])
	}

	// Wait for joiner handshake message
	if err := c.awaitJoinerHandshake(); err != nil {
		_ = c.Close()
		return nil, err
	}

	return c, nil
}

// ConnectJoinerWithCode connects to the relay using a short pairing code, performing PAKE key agreement.
func ConnectJoinerWithCode(relayURL string, sid string, code string) (*Client, error) {
	wsEndpoint, err := constructWSEndpoint(relayURL, sid)
	if err != nil {
		return nil, err
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}

	normCode := crypto.NormalizePairingCode(code)
	c := &Client{
		conn:      conn,
		role:      crypto.RoleJoiner,
		sid:       sid,
		code:      normCode,
		relayURL:  relayURL,
		counter:   crypto.NewNonceCounter(crypto.RoleJoiner),
		validator: crypto.NewNonceValidator(crypto.RoleInitiator),
		closed:    make(chan struct{}),
	}

	// 1. Initialize PAKE Joiner and generate pake_init frame
	pakeInstance, initBytes, err := crypto.PAKEJoinerInit(normCode)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	initMsg := protocol.NewPAKEInitMessage(initBytes)
	initJSON, err := json.Marshal(initMsg)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	c.writeMu.Lock()
	err = c.conn.WriteMessage(websocket.TextMessage, initJSON)
	c.writeMu.Unlock()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to send PAKE init: %w", err)
	}

	// 2. Await pake_reply from Initiator
	for {
		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("read PAKE reply failed: %w", err)
		}
		if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
			continue
		}

		if protocol.IsPAKEReplyFrame(data) {
			var replyMsg protocol.PAKEMessage
			if err := json.Unmarshal(data, &replyMsg); err != nil {
				_ = c.Close()
				return nil, fmt.Errorf("failed to unmarshal PAKE reply: %w", err)
			}
			replyBytes, err := replyMsg.DecodeData()
			if err != nil {
				_ = c.Close()
				return nil, fmt.Errorf("failed to decode PAKE reply data: %w", err)
			}

			key, err := crypto.PAKEJoinerFinalize(pakeInstance, replyBytes)
			if err != nil {
				_ = c.Close()
				return nil, fmt.Errorf("PAKE key finalization failed: %w", err)
			}

			aead, err := crypto.NewAEAD(key)
			if err != nil {
				_ = c.Close()
				return nil, fmt.Errorf("failed to initialize AEAD cipher: %w", err)
			}
			c.aead = aead
			return c, nil
		}
	}
}

// ConnectJoiner connects to the relay as the joiner, sends its public key to the initiator, and derives the session key.
func ConnectJoiner(relayURL string, sid string, initiatorPubHex string, privKey *ecdh.PrivateKey) (*Client, error) {
	wsEndpoint, err := constructWSEndpoint(relayURL, sid)
	if err != nil {
		return nil, err
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to relay: %w", err)
	}

	c := &Client{
		conn:       conn,
		privKey:    privKey,
		pubKeyHex:  hex.EncodeToString(privKey.PublicKey().Bytes()),
		peerPubHex: strings.ToLower(initiatorPubHex),
		role:       crypto.RoleJoiner,
		sid:        sid,
		relayURL:   relayURL,
		counter:    crypto.NewNonceCounter(crypto.RoleJoiner),
		validator:  crypto.NewNonceValidator(crypto.RoleInitiator),
		closed:     make(chan struct{}),
	}

	// 1. Send handshake message to initiator
	hs := protocol.NewHandshakeMessage(c.pubKeyHex)
	hsBytes, err := json.Marshal(hs)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	c.writeMu.Lock()
	err = c.conn.WriteMessage(websocket.TextMessage, hsBytes)
	c.writeMu.Unlock()
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to send handshake to initiator: %w", err)
	}

	// 2. Derive key from initiator's public key
	peerPubBytes, err := hex.DecodeString(c.peerPubHex)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("invalid initiator public key: %w", err)
	}

	secret, err := crypto.ComputeSharedSecret(c.privKey, peerPubBytes)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to compute shared secret: %w", err)
	}

	key, err := crypto.DeriveSessionKey(secret)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to derive session key: %w", err)
	}

	aead, err := crypto.NewAEAD(key)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("failed to initialize AEAD cipher: %w", err)
	}
	c.aead = aead

	return c, nil
}

func (c *Client) awaitJoinerHandshake() error {
	// Loop until handshake received (skipping keepalives)
	for {
		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("%w: read failed: %v", ErrHandshakeFailed, err)
		}
		if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
			continue
		}

		var hs protocol.HandshakeMessage
		if err := json.Unmarshal(data, &hs); err == nil && hs.Type == protocol.TypeHandshake {
			c.peerPubHex = strings.ToLower(hs.Pub)
			peerPubBytes, err := hex.DecodeString(c.peerPubHex)
			if err != nil || len(peerPubBytes) != 32 {
				return fmt.Errorf("%w: invalid peer public key in handshake", ErrHandshakeFailed)
			}

			secret, err := crypto.ComputeSharedSecret(c.privKey, peerPubBytes)
			if err != nil {
				return fmt.Errorf("%w: compute shared secret: %v", ErrHandshakeFailed, err)
			}

			key, err := crypto.DeriveSessionKey(secret)
			if err != nil {
				return fmt.Errorf("%w: derive session key: %v", ErrHandshakeFailed, err)
			}

			aead, err := crypto.NewAEAD(key)
			if err != nil {
				return fmt.Errorf("%w: new AEAD: %v", ErrHandshakeFailed, err)
			}
			c.aead = aead
			return nil
		}

		if protocol.IsPAKEInitFrame(data) {
			var pm protocol.PAKEMessage
			if err := json.Unmarshal(data, &pm); err == nil && c.code != "" {
				initBytes, err := pm.DecodeData()
				if err == nil {
					replyBytes, key, err := crypto.PAKEInitiatorRespond(c.code, initBytes)
					if err == nil {
						replyMsg := protocol.NewPAKEReplyMessage(replyBytes)
						replyJSON, _ := json.Marshal(replyMsg)
						c.writeMu.Lock()
						_ = c.conn.WriteMessage(websocket.TextMessage, replyJSON)
						c.writeMu.Unlock()

						aead, err := crypto.NewAEAD(key)
						if err == nil {
							c.stateMu.Lock()
							c.aead = aead
							c.counter = crypto.NewNonceCounter(crypto.RoleInitiator)
							c.validator = crypto.NewNonceValidator(crypto.RoleJoiner)
							c.stateMu.Unlock()
							return nil
						}
					}
				}
			}
		}
	}
}

// SendPayload encrypts and sends an InnerPayload through the wire envelope.
func (c *Client) SendPayload(payload *protocol.InnerPayload) error {
	c.stateMu.RLock()
	aead := c.aead
	counter := c.counter
	c.stateMu.RUnlock()

	if aead == nil {
		return errors.New("client handshake not completed")
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to serialize payload: %w", err)
	}

	seq, nonce := counter.Next()
	ciphertext := crypto.Encrypt(aead, nonce, payloadJSON)

	envelope := protocol.NewWireEnvelope(seq, nonce, ciphertext)
	envelopeJSON, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("failed to serialize envelope: %w", err)
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.conn.WriteMessage(websocket.TextMessage, envelopeJSON)
}

// SendText sends a plain text message.
func (c *Client) SendText(text string) error {
	return c.SendPayload(protocol.NewTextMessage(text))
}

// ReadPayload reads and decrypts the next inner payload from the peer.
func (c *Client) ReadPayload() (*protocol.InnerPayload, error) {
	for {
		select {
		case <-c.closed:
			return nil, ErrSessionClosed
		default:
		}

		msgType, data, err := c.conn.ReadMessage()
		if err != nil {
			return nil, err
		}
		if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
			continue
		}

		// Handle incoming handshake frames from reconnecting or new peers
		if protocol.IsHandshakeFrame(data) {
			var hs protocol.HandshakeMessage
			if err := json.Unmarshal(data, &hs); err == nil && hs.Type == protocol.TypeHandshake {
				peerPubBytes, err := hex.DecodeString(strings.ToLower(hs.Pub))
				if err == nil && len(peerPubBytes) == 32 {
					secret, err := crypto.ComputeSharedSecret(c.privKey, peerPubBytes)
					if err == nil {
						key, err := crypto.DeriveSessionKey(secret)
						if err == nil {
							newAEAD, err := crypto.NewAEAD(key)
							if err == nil {
								c.stateMu.Lock()
								c.peerPubHex = strings.ToLower(hs.Pub)
								c.aead = newAEAD
								c.counter = crypto.NewNonceCounter(c.role)
								expectedPeerRole := crypto.RoleJoiner
								if c.role == crypto.RoleJoiner {
									expectedPeerRole = crypto.RoleInitiator
								}
								c.validator = crypto.NewNonceValidator(expectedPeerRole)
								c.stateMu.Unlock()

								if c.OnPeerConnected != nil {
									c.OnPeerConnected()
								}
								// Handshake processed, continue loop to read subsequent data frame
								continue
							}
						}
					}
				}
			}
		}

		if protocol.IsPAKEInitFrame(data) {
			var pm protocol.PAKEMessage
			if err := json.Unmarshal(data, &pm); err == nil && c.code != "" {
				initBytes, err := pm.DecodeData()
				if err == nil {
					replyBytes, key, err := crypto.PAKEInitiatorRespond(c.code, initBytes)
					if err == nil {
						replyMsg := protocol.NewPAKEReplyMessage(replyBytes)
						replyJSON, _ := json.Marshal(replyMsg)
						c.writeMu.Lock()
						_ = c.conn.WriteMessage(websocket.TextMessage, replyJSON)
						c.writeMu.Unlock()

						newAEAD, err := crypto.NewAEAD(key)
						if err == nil {
							c.stateMu.Lock()
							c.aead = newAEAD
							c.counter = crypto.NewNonceCounter(c.role)
							expectedPeerRole := crypto.RoleJoiner
							if c.role == crypto.RoleJoiner {
								expectedPeerRole = crypto.RoleInitiator
							}
							c.validator = crypto.NewNonceValidator(expectedPeerRole)
							c.stateMu.Unlock()

							if c.OnPeerConnected != nil {
								c.OnPeerConnected()
							}
							continue
						}
					}
				}
			}
		}

		var env protocol.WireEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			return nil, fmt.Errorf("failed to unmarshal wire envelope: %w", err)
		}

		nonce, ciphertext, err := env.DecodeComponents()
		if err != nil {
			return nil, err
		}

		c.stateMu.RLock()
		validator := c.validator
		aead := c.aead
		c.stateMu.RUnlock()

		// Validate nonce monotonically and check directional prefix
		if err := validator.Validate(nonce, env.Seq); err != nil {
			return nil, fmt.Errorf("nonce validation failed: %w", err)
		}

		plaintext, err := crypto.Decrypt(aead, nonce, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %w", err)
		}

		var payload protocol.InnerPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return nil, fmt.Errorf("failed to parse decrypted inner payload: %w", err)
		}

		return &payload, nil
	}
}

// Close gracefully closes the client connection.
func (c *Client) Close() error {
	var err error
	c.onceClose.Do(func() {
		close(c.closed)
		c.writeMu.Lock()
		_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
		err = c.conn.Close()
		c.writeMu.Unlock()
	})
	return err
}

func constructWSEndpoint(relayURL string, sid string) (string, error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return "", fmt.Errorf("invalid relay URL: %w", err)
	}
	q := u.Query()
	q.Set("sid", sid)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
