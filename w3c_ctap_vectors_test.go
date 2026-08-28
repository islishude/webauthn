package webauthn_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

func TestW3CLevel3PRFCTAPVectors(t *testing.T) {
	t.Parallel()

	fixture := loadW3CFixture[w3cPRFCTAPFixture](t, "prf-ctap.json")
	seed := decodeW3CHex(t, fixture.Seed)
	platformPrivate := decodeW3CHex(t, fixture.PlatformKeyAgreementPrivateKey)
	authenticatorPublic := append([]byte{0x04}, decodeW3CHex(t, fixture.AuthenticatorKeyAgreementPublicKeyX)...)
	authenticatorPublic = append(authenticatorPublic, decodeW3CHex(t, fixture.AuthenticatorKeyAgreementPublicKeyY)...)
	credentialRandom := decodeW3CHex(t, fixture.AuthenticatorCredRandom)
	curve := ecdh.P256()
	privateKey, err := curve.NewPrivateKey(platformPrivate)
	if err != nil {
		t.Fatalf("NewPrivateKey() error = %v", err)
	}
	publicKey, err := curve.NewPublicKey(authenticatorPublic)
	if err != nil {
		t.Fatalf("NewPublicKey() error = %v", err)
	}
	sharedPoint, err := privateKey.ECDH(publicKey)
	if err != nil {
		t.Fatalf("ECDH() error = %v", err)
	}

	for _, vector := range fixture.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			t.Parallel()

			sharedSecret := w3cCTAPSharedSecret(t, vector.PINProtocol, sharedPoint)
			assertW3CBytes(t, "shared_secret", sharedSecret, vector.SharedSecret)

			first := decodeW3CHex(t, vector.PRFEvalFirst)
			salt1 := w3cPRFSalt(first)
			assertW3CBytes(t, "salt1", salt1, vector.Salt1)
			var second, salt2 []byte
			if vector.PRFEvalSecond != "" {
				second = decodeW3CHex(t, vector.PRFEvalSecond)
				salt2 = w3cPRFSalt(second)
				assertW3CBytes(t, "salt2", salt2, vector.Salt2)
			}
			salts := append(append([]byte{}, salt1...), salt2...)
			saltIV := w3cCTAPIV(t, seed, vector.PINProtocol, vector.SaltIVDerivationByte)
			saltEnc := w3cCTAPEncrypt(t, vector.PINProtocol, sharedSecret, saltIV, salts)
			assertW3CBytes(t, "salt_enc", saltEnc, vector.SaltEnc)
			if decrypted := w3cCTAPDecrypt(t, vector.PINProtocol, sharedSecret, saltEnc); !bytes.Equal(decrypted, salts) {
				t.Fatalf("decrypted salts = %x, want %x", decrypted, salts)
			}

			output1 := w3cHMACSHA256(credentialRandom, salt1)
			assertW3CBytes(t, "output1", output1, vector.Output1)
			var output2 []byte
			if salt2 != nil {
				output2 = w3cHMACSHA256(credentialRandom, salt2)
				assertW3CBytes(t, "output2", output2, vector.Output2)
			}
			outputs := append(append([]byte{}, output1...), output2...)
			outputIV := w3cCTAPIV(t, seed, vector.PINProtocol, vector.OutputIVDerivationByte)
			outputEnc := w3cCTAPEncrypt(t, vector.PINProtocol, sharedSecret, outputIV, outputs)
			assertW3CBytes(t, "output_enc", outputEnc, vector.OutputEnc)
			results := w3cCTAPDecrypt(t, vector.PINProtocol, sharedSecret, outputEnc)
			if len(results) != len(outputs) || len(results) < sha256.Size {
				t.Fatalf("decrypted results length = %d, want %d", len(results), len(outputs))
			}
			assertW3CBytes(t, "prf_results_first", results[:sha256.Size], vector.PRFResultsFirst)
			if vector.PRFResultsSecond != "" {
				assertW3CBytes(t, "prf_results_second", results[sha256.Size:], vector.PRFResultsSecond)
			} else if len(results) != sha256.Size {
				t.Fatalf("unexpected second PRF result: %x", results[sha256.Size:])
			}
		})
	}
}

func w3cCTAPSharedSecret(t *testing.T, protocolVersion int, sharedPoint []byte) []byte {
	t.Helper()
	switch protocolVersion {
	case 1:
		digest := sha256.Sum256(sharedPoint)
		return append([]byte{}, digest[:]...)
	case 2:
		hmacKey, err := hkdf.Key(sha256.New, sharedPoint, make([]byte, sha256.Size), "CTAP2 HMAC key", sha256.Size)
		if err != nil {
			t.Fatalf("HKDF HMAC key error = %v", err)
		}
		aesKey, err := hkdf.Key(sha256.New, sharedPoint, make([]byte, sha256.Size), "CTAP2 AES key", sha256.Size)
		if err != nil {
			t.Fatalf("HKDF AES key error = %v", err)
		}
		return append(hmacKey, aesKey...)
	default:
		t.Fatalf("unsupported W3C PIN protocol %d", protocolVersion)
		return nil
	}
}

func w3cPRFSalt(input []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("WebAuthn PRF"))
	_, _ = hash.Write([]byte{0x00})
	_, _ = hash.Write(input)
	return hash.Sum(nil)
}

func w3cCTAPIV(t *testing.T, seed []byte, protocolVersion int, derivationByte int) []byte {
	t.Helper()
	if protocolVersion == 1 {
		if derivationByte != 0 {
			t.Fatalf("PIN protocol 1 IV derivation byte = %d, want zero", derivationByte)
		}
		return make([]byte, aes.BlockSize)
	}
	if derivationByte < 1 || derivationByte > 255 {
		t.Fatalf("PIN protocol 2 IV derivation byte = %d, want 1..255", derivationByte)
	}
	encodedDerivationByte := byte(derivationByte) //nolint:gosec // Explicit range check above proves this conversion lossless.
	input := append(append([]byte{}, seed...), encodedDerivationByte)
	digest := sha256.Sum256(input)
	return append([]byte{}, digest[:aes.BlockSize]...)
}

func w3cCTAPEncrypt(t *testing.T, protocolVersion int, sharedSecret []byte, iv []byte, plaintext []byte) []byte {
	t.Helper()
	key := sharedSecret
	if protocolVersion == 2 {
		if len(sharedSecret) != sha256.Size*2 {
			t.Fatalf("PIN protocol 2 shared secret length = %d", len(sharedSecret))
		}
		key = sharedSecret[sha256.Size:]
	}
	if len(plaintext)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		t.Fatalf("invalid AES-CBC input: plaintext=%d iv=%d", len(plaintext), len(iv))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	ciphertext := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	if protocolVersion == 2 {
		return append(append([]byte{}, iv...), ciphertext...)
	}
	return ciphertext
}

func w3cCTAPDecrypt(t *testing.T, protocolVersion int, sharedSecret []byte, ciphertext []byte) []byte {
	t.Helper()
	key := sharedSecret
	iv := make([]byte, aes.BlockSize)
	if protocolVersion == 2 {
		if len(sharedSecret) != sha256.Size*2 || len(ciphertext) < aes.BlockSize {
			t.Fatalf("invalid PIN protocol 2 ciphertext or shared secret")
		}
		key = sharedSecret[sha256.Size:]
		iv = append([]byte{}, ciphertext[:aes.BlockSize]...)
		ciphertext = ciphertext[aes.BlockSize:]
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		t.Fatalf("invalid AES-CBC ciphertext length %d", len(ciphertext))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher() error = %v", err)
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return plaintext
}

func w3cHMACSHA256(key, message []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(message)
	return mac.Sum(nil)
}

func assertW3CBytes(t *testing.T, field string, got []byte, wantHex string) {
	t.Helper()
	want := decodeW3CHex(t, wantHex)
	if !bytes.Equal(got, want) {
		t.Fatalf("%s = %x, want %x", field, got, want)
	}
}
