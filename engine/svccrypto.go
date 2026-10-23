package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// Secret Service session transports per the freedesktop draft spec:
//
//	plain                                    — pass-through; params ignored
//	dh-ietf1024-sha256-aes128-cbc-pkcs7      — RFC 2409 Oakley Group 2 DH,
//	                                           HKDF-SHA256, AES-128-CBC + PKCS#7
//
// A session is negotiated by Service.OpenSession(algorithm, input) and then
// wraps every Secret body's (params, value) pair. For plain, params is
// ignored and value is the plaintext. For DH, the client sends its public
// key as the OpenSession input, we reply with ours, and each wrapped secret
// carries a fresh 16-byte IV in params and the ciphertext in value.
//
// The DH path is the wire shape libsecret prefers; plain exists because
// go-keyring (gh, docker credential helpers, our own ssStore) is plain-only.
// Plain means a same-UID bus monitor can read secret bodies — the name owner
// is the trust root regardless, so this is a documented ceiling, not a bug.

const (
	svcAlgPlain = "plain"
	svcAlgDH    = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

// svcSessionCodec wraps and unwraps one session's secret bodies.
type svcSessionCodec interface {
	encrypt(secret []byte) (params, value []byte, err error)
	decrypt(params, value []byte) ([]byte, error)
}

// svcPlainCodec passes secret bodies through unmodified.
type svcPlainCodec struct{}

func (svcPlainCodec) encrypt(secret []byte) (params, value []byte, err error) {
	return nil, secret, nil
}

func (svcPlainCodec) decrypt(_, value []byte) ([]byte, error) { return value, nil }

// RFC 2409 Second Oakley Group: 1024-bit MODP prime, generator 2.
var svcDHPrime, _ = new(big.Int).SetString(
	"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"+
		"FFFFFFFFFFFFFFFF", 16)

var svcDHGenerator = big.NewInt(2)

// svcDHCodec implements dh-ietf1024-sha256-aes128-cbc-pkcs7.
type svcDHCodec struct {
	key []byte // 16-byte AES key derived via HKDF-SHA256
}

// svcNewDHKeypair generates an ephemeral DH private key and returns it with
// the public key (big-endian) the OpenSession call sends back to the client.
func svcNewDHKeypair() (priv *big.Int, pub []byte, err error) {
	// priv in [2, p-2]
	limit := new(big.Int).Sub(svcDHPrime, big.NewInt(3))
	priv, err = rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, nil, err
	}
	priv.Add(priv, big.NewInt(2))
	pubInt := new(big.Int).Exp(svcDHGenerator, priv, svcDHPrime)
	return priv, pubInt.FillBytes(make([]byte, 128)), nil
}

// svcNewDHCodec derives the session key from the peer's public key.
// The shared secret is encoded fixed 128-byte big-endian before HKDF —
// the unpadded encoding is the docker/secrets-engine#547 bug class.
func svcNewDHCodec(priv *big.Int, peerPub []byte) (*svcDHCodec, error) {
	peer := new(big.Int).SetBytes(peerPub)
	// Reject degenerate keys: 0, 1, p-1, p, and out-of-range peers all
	// collapse the shared secret to a known value.
	limit := new(big.Int).Sub(svcDHPrime, big.NewInt(1))
	if peer.Cmp(big.NewInt(1)) <= 0 || peer.Cmp(limit) >= 0 {
		return nil, errors.New("degenerate DH public key")
	}
	shared := new(big.Int).Exp(peer, priv, svcDHPrime)
	ikm := shared.FillBytes(make([]byte, 128))
	key, err := hkdf.Key(sha256.New, ikm, nil, "", 16)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return &svcDHCodec{key: key}, nil
}

func (c *svcDHCodec) encrypt(secret []byte) (params, value []byte, err error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, err
	}
	plain := pkcs7Pad(secret, aes.BlockSize)
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return iv, out, nil
}

func (c *svcDHCodec) decrypt(params, value []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	if len(params) != aes.BlockSize {
		return nil, errors.New("bad IV length")
	}
	if len(value) == 0 || len(value)%aes.BlockSize != 0 {
		return nil, errors.New("bad ciphertext length")
	}
	out := make([]byte, len(value))
	cipher.NewCBCDecrypter(block, params).CryptBlocks(out, value)
	return pkcs7Unpad(out, aes.BlockSize)
}

// pkcs7Pad appends PKCS#7 padding to a block boundary.
func pkcs7Pad(in []byte, blockSize int) []byte {
	n := blockSize - len(in)%blockSize
	out := make([]byte, len(in)+n)
	copy(out, in)
	for i := len(in); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// pkcs7Unpad strips and validates PKCS#7 padding.
func pkcs7Unpad(in []byte, blockSize int) ([]byte, error) {
	if len(in) == 0 || len(in)%blockSize != 0 {
		return nil, errors.New("bad padded length")
	}
	n := int(in[len(in)-1])
	if n == 0 || n > blockSize || n > len(in) {
		return nil, errors.New("bad padding")
	}
	if !bytes.Equal(in[len(in)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return nil, errors.New("bad padding")
	}
	return in[:len(in)-n], nil
}
