package main

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"math/big"
	"testing"

	xhkdf "golang.org/x/crypto/hkdf"
)

func TestSvcPlainCodecRoundTrip(t *testing.T) {
	c := svcPlainCodec{}
	p, v, err := c.encrypt([]byte("s3cr3t"))
	if err != nil {
		t.Fatal(err)
	}
	if p != nil || string(v) != "s3cr3t" {
		t.Fatalf("plain must pass through: params=%v value=%q", p, v)
	}
	got, err := c.decrypt(nil, v)
	if err != nil || string(got) != "s3cr3t" {
		t.Fatalf("decrypt: %v %q", err, got)
	}
}

func TestSvcDHCodecRoundTrip(t *testing.T) {
	priv, pub, err := svcNewDHKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 128 {
		t.Fatalf("pubkey must be fixed 128 bytes, got %d", len(pub))
	}
	c, err := svcNewDHCodec(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	iv, ct, err := c.encrypt([]byte("hello world"))
	if err != nil {
		t.Fatal(err)
	}
	if len(iv) != aes.BlockSize || len(ct)%aes.BlockSize != 0 {
		t.Fatalf("bad wire shape: iv=%d ct=%d", len(iv), len(ct))
	}
	got, err := c.decrypt(iv, ct)
	if err != nil || string(got) != "hello world" {
		t.Fatalf("round-trip: %v %q", err, got)
	}
}

// Both sides of a DH exchange must derive the same key — simulates the real
// client/server split: server sends pub, client sends peer pub, both derive.
func TestSvcDHSharedSecretSymmetry(t *testing.T) {
	serverPriv, serverPub, err := svcNewDHKeypair()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, clientPub, err := svcNewDHKeypair()
	if err != nil {
		t.Fatal(err)
	}
	serverCodec, err := svcNewDHCodec(serverPriv, clientPub)
	if err != nil {
		t.Fatal(err)
	}
	clientCodec, err := svcNewDHCodec(clientPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(serverCodec.key, clientCodec.key) {
		t.Fatal("derived keys differ — DH symmetry broken")
	}
	// And a client-side encrypt must server-decrypt.
	iv, ct, err := clientCodec.encrypt([]byte("from client"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverCodec.decrypt(iv, ct)
	if err != nil || string(got) != "from client" {
		t.Fatalf("cross-side decrypt: %v %q", err, got)
	}
}

// Regression pin: the derived AES key for a fixed peer input must be stable.
// Shared secret is encoded fixed 128-byte before HKDF — if padding regresses,
// this key changes and clients like libsecret fail to decrypt.
func TestSvcDHDerivedKeyGolden(t *testing.T) {
	// priv = 5 (small but valid), peer = 2^5 mod p — both computable in-test.
	priv := big.NewInt(5)
	peerInt := new(big.Int).Exp(svcDHGenerator, priv, svcDHPrime)
	// priv^2 mod p for a fixed second key.
	otherPriv := big.NewInt(7)
	otherPub := new(big.Int).Exp(svcDHGenerator, otherPriv, svcDHPrime)

	c1, err := svcNewDHCodec(otherPriv, peerInt.FillBytes(make([]byte, 128)))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := svcNewDHCodec(priv, otherPub.FillBytes(make([]byte, 128)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c1.key, c2.key) {
		t.Fatal("symmetry failed on fixed inputs")
	}
	// Cross-check against x/crypto/hkdf — a second HKDF impl must agree, so the
	// pin below is an interop pin, not a self-consistency check.
	shared := new(big.Int).Exp(peerInt, otherPriv, svcDHPrime).FillBytes(make([]byte, 128))
	r := xhkdf.New(sha256.New, shared, nil, nil)
	xkey := make([]byte, 16)
	if _, err := io.ReadFull(r, xkey); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(xkey, c1.key) {
		t.Fatal("stdlib hkdf and x/crypto hkdf disagree")
	}
	// Golden pin — generated once, asserts derivation is stable across refactors.
	const golden = "aff01ea9e17aee57325765b5e9f3c619"
	if got := hex.EncodeToString(c1.key); got != golden {
		t.Fatalf("derived key drifted: got %s want %s", got, golden)
	}
}

// Peer pubkeys that collapse the shared secret must be rejected:
// 0, 1, p-1, p, and out-of-range values all force known secrets.
func TestSvcDHDegeneratePeerRejected(t *testing.T) {
	priv, _, err := svcNewDHKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"zero":    big.NewInt(0).Bytes(),
		"one":     big.NewInt(1).Bytes(),
		"p-1":     new(big.Int).Sub(svcDHPrime, big.NewInt(1)).FillBytes(make([]byte, 128)),
		"p":       svcDHPrime.FillBytes(make([]byte, 128)),
		"p+1":     new(big.Int).Add(svcDHPrime, big.NewInt(1)).FillBytes(make([]byte, 128)),
		"over128": new(big.Int).Lsh(big.NewInt(1), 1200).Bytes(), // >128 bytes on the wire
		"empty":   {},
	}
	for name, peer := range cases {
		if _, err := svcNewDHCodec(priv, peer); err == nil {
			t.Errorf("%s: degenerate pubkey accepted", name)
		}
	}
}

func TestSvcDHWrongKeyDecryptFails(t *testing.T) {
	privA, _, _ := svcNewDHKeypair()
	privB, pubB, _ := svcNewDHKeypair()
	// codec built from a DIFFERENT peer than the encryptor's key
	ca, err := svcNewDHCodec(privA, pubB)
	if err != nil {
		t.Fatal(err)
	}
	_, pubA, err := svcNewDHKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cb, err := svcNewDHCodec(privB, pubA)
	if err != nil {
		t.Fatal(err)
	}
	iv, ct, err := cb.encrypt([]byte("secret under the wrong key pairing"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.decrypt(iv, ct); err == nil {
		t.Fatal("wrong-key decrypt must fail padding validation")
	}
}

func TestPKCS7Padding(t *testing.T) {
	// exact block multiple gets a full pad block
	if got := len(pkcs7Pad(make([]byte, 16), 16)); got != 32 {
		t.Fatalf("pad: %d", got)
	}
	// unpad validation rejects malformed tails (last byte says 4 but a pad
	// byte differs)
	bad := make([]byte, 16)
	bad[15] = 4
	if _, err := pkcs7Unpad(bad, 16); err == nil {
		t.Fatal("bad padding accepted")
	}
	// and rejects a pad length larger than the block
	bad2 := make([]byte, 16)
	bad2[15] = 17
	if _, err := pkcs7Unpad(bad2, 16); err == nil {
		t.Fatal("oversized pad accepted")
	}
	out, err := pkcs7Unpad(pkcs7Pad([]byte("abc"), 16), 16)
	if err != nil || string(out) != "abc" {
		t.Fatalf("pad/unpad: %v %q", err, out)
	}
	// empty input pads to one block
	out, err = pkcs7Unpad(pkcs7Pad(nil, 16), 16)
	if err != nil || len(out) != 0 {
		t.Fatalf("empty round-trip: %v", err)
	}
	// non-multiple input to unpad fails
	if _, err := pkcs7Unpad(make([]byte, 17), 16); err == nil {
		t.Fatal("non-block-multiple unpad accepted")
	}
}

// Random sanity: distinct keypairs derive distinct keys (no accidental
// constant-key bug).
func TestSvcDHDistinctKeys(t *testing.T) {
	priv1, _, _ := svcNewDHKeypair()
	priv2, pub, _ := svcNewDHKeypair()
	c1, err := svcNewDHCodec(priv1, pub)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := svcNewDHCodec(priv2, pub)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1.key, c2.key) {
		t.Fatal("distinct privkeys derived the same key")
	}
	_ = rand.Reader // keep import honest if refactored
}
