package bundle

import (
	"bytes"
	"encoding/base64"
	"testing"
	"time"
)

var testTime = time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

func mustGenerate(t *testing.T, suite Suite) *KeyPair {
	t.Helper()
	kp, err := Generate(suite)
	if err != nil {
		t.Fatalf("Generate(%s): %v", suite, err)
	}
	return kp
}

func publicHalves(t *testing.T, kp *KeyPair) (pq, ec []byte) {
	t.Helper()
	pub, err := MarshalPublic(kp)
	if err != nil {
		t.Fatal(err)
	}
	pq, ec, err = ParsePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pq, ec
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, suite := range []Suite{SuiteHybridMLDSA87, SuiteHybridSLHDSA} {
		t.Run(string(suite), func(t *testing.T) {
			kp := mustGenerate(t, suite)
			doc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)

			b, err := Sign(kp, doc, testTime)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			pq, ec := publicHalves(t, kp)
			if err := Verify(b, doc, pq, ec); err != nil {
				t.Errorf("a freshly signed document should verify: %v", err)
			}
		})
	}
}

func TestVerifyRejectsAlteredDocument(t *testing.T) {
	kp := mustGenerate(t, SuiteHybridMLDSA87)
	doc := []byte(`{"specVersion":"1.6","components":[]}`)
	b, err := Sign(kp, doc, testTime)
	if err != nil {
		t.Fatal(err)
	}
	pq, ec := publicHalves(t, kp)

	altered := []byte(`{"specVersion":"1.6","components":[{"name":"snuck-in"}]}`)
	if err := Verify(b, altered, pq, ec); err == nil {
		t.Fatal("a document altered after signing must not verify")
	}
}

// TestVerifyRejectsForeignKey covers the substitution attack the design is
// built against: an attacker who replaces the document AND re-signs it with
// their own key produces a bundle that is internally consistent. Checking the
// bundle's own key against one the caller already trusts is what defeats it.
func TestVerifyRejectsForeignKey(t *testing.T) {
	mine := mustGenerate(t, SuiteHybridMLDSA87)
	theirs := mustGenerate(t, SuiteHybridMLDSA87)

	doc := []byte(`{"specVersion":"1.6"}`)
	forged, err := Sign(theirs, doc, testTime)
	if err != nil {
		t.Fatal(err)
	}

	// The forged bundle verifies perfectly against its own embedded key...
	theirPQ, theirEC := publicHalves(t, theirs)
	if err := Verify(forged, doc, theirPQ, theirEC); err != nil {
		t.Fatalf("the forgery should be internally consistent: %v", err)
	}
	// ...and must still be refused against the key we actually trust.
	myPQ, myEC := publicHalves(t, mine)
	if err := Verify(forged, doc, myPQ, myEC); err == nil {
		t.Fatal("a bundle signed by a different key must not verify against ours")
	}
}

// TestVerifyRequiresBothSignatures is the reason for signing twice. If either
// half could be dropped or corrupted without failing, the hybrid would be
// decoration.
func TestVerifyRequiresBothSignatures(t *testing.T) {
	kp := mustGenerate(t, SuiteHybridMLDSA87)
	doc := []byte(`{"specVersion":"1.6"}`)
	pq, ec := publicHalves(t, kp)

	t.Run("post-quantum half corrupted", func(t *testing.T) {
		b, _ := Sign(kp, doc, testTime)
		b.PQSignature = corrupt(t, b.PQSignature)
		if err := Verify(b, doc, pq, ec); err == nil {
			t.Error("a broken post-quantum signature must fail even though the classical one holds")
		}
	})

	t.Run("classical half corrupted", func(t *testing.T) {
		b, _ := Sign(kp, doc, testTime)
		b.ECSignature = corrupt(t, b.ECSignature)
		if err := Verify(b, doc, pq, ec); err == nil {
			t.Error("a broken classical signature must fail even though the post-quantum one holds")
		}
	})
}

// TestSuiteIsAuthenticated guards against a downgrade: the suite name is inside
// the signed payload, so relabelling a bundle breaks both signatures rather
// than merely mislabelling it.
func TestSuiteIsAuthenticated(t *testing.T) {
	kp := mustGenerate(t, SuiteHybridMLDSA87)
	doc := []byte(`{"specVersion":"1.6"}`)
	b, _ := Sign(kp, doc, testTime)
	pq, ec := publicHalves(t, kp)

	b.Suite = SuiteHybridSLHDSA
	if err := Verify(b, doc, pq, ec); err == nil {
		t.Error("relabelling the suite must not produce a bundle that verifies")
	}
}

func TestSignedTimestampIsAuthenticated(t *testing.T) {
	kp := mustGenerate(t, SuiteHybridMLDSA87)
	doc := []byte(`{"specVersion":"1.6"}`)
	b, _ := Sign(kp, doc, testTime)
	pq, ec := publicHalves(t, kp)

	b.SignedAt = "2020-01-01T00:00:00Z"
	if err := Verify(b, doc, pq, ec); err == nil {
		t.Error("backdating a bundle must break its signatures")
	}
}

func TestKeyRoundTripThroughPEM(t *testing.T) {
	kp := mustGenerate(t, SuiteHybridMLDSA87)
	data, err := MarshalPrivate(kp)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParsePrivate(data)
	if err != nil {
		t.Fatalf("ParsePrivate: %v", err)
	}
	if back.Suite != kp.Suite {
		t.Errorf("suite lost in round trip: %s -> %s", kp.Suite, back.Suite)
	}

	// A key that survives the round trip must still produce verifiable
	// signatures; equality of bytes is not the property that matters.
	doc := []byte("round trip")
	b, err := Sign(back, doc, testTime)
	if err != nil {
		t.Fatal(err)
	}
	pq, ec := publicHalves(t, kp)
	if err := Verify(b, doc, pq, ec); err != nil {
		t.Errorf("a reloaded key should sign verifiably against the original public key: %v", err)
	}
}

func TestPrivateKeyFileIsNotAPublicKeyFile(t *testing.T) {
	kp := mustGenerate(t, SuiteHybridMLDSA87)
	priv, _ := MarshalPrivate(kp)
	pub, _ := MarshalPublic(kp)
	if bytes.Equal(priv, pub) {
		t.Fatal("private and public material must not be the same bytes")
	}
	if _, _, err := ParsePublic(priv); err == nil {
		t.Error("a private key file should not parse as a public key file")
	}
}

// corrupt flips a byte inside a base64 payload, leaving it decodable.
func corrupt(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 {
		t.Fatalf("undecodable signature in fixture: %v", err)
	}
	raw[len(raw)/2] ^= 0xFF
	return base64.StdEncoding.EncodeToString(raw)
}
