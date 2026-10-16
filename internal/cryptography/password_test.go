package cryptography_test

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/cryptography"
)

// Known answers for "password" and a salt of sixteen 0x01 bytes, computed with golang.org/x/crypto/argon2.
const (
	defaultsAnswer = "$argon2id$v=19$m=19456,t=2,p=1$AQEBAQEBAQEBAQEBAQEBAQ$FGlXh8itGiEPkJl4VLoHXFF7l5JO1RPiRKoFjEigPqM"
	smallAnswer    = "$argon2id$v=19$m=64,t=1,p=1$AQEBAQEBAQEBAQEBAQEBAQ$9jDiIO+Ksrxrw5/x3GoDmEe2iEnKPJY3GTfvU9uZ21U"
)

// rawBase64 encodes n bytes of 0x01 as a PHC salt or key field.
func rawBase64(n int) string {
	return base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, n))
}

func TestArgon2id(t *testing.T) {
	t.Run("a password verifies against its own hash", func(t *testing.T) {
		h := cryptography.NewArgon2id(cryptography.CryptoRandom{})
		password := []byte("correct horse battery staple")

		encoded, err := h.Hash(password)
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}

		ok, err := h.Verify(password, encoded)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !ok {
			t.Errorf("got false, want true")
		}
	})

	t.Run("a different password does not verify", func(t *testing.T) {
		h := cryptography.NewArgon2id(cryptography.CryptoRandom{})

		encoded, err := h.Hash([]byte("correct horse battery staple"))
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}

		ok, err := h.Verify([]byte("correct horse battery stapler"), encoded)
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if ok {
			t.Errorf("got true, want false")
		}
	})

	t.Run("a hash is the known answer for a fixed salt", func(t *testing.T) {
		h := cryptography.NewArgon2id(fixedRandom(bytes.Repeat([]byte{0x01}, 16)))

		got, err := h.Hash([]byte("password"))
		if err != nil {
			t.Fatalf("Hash: %v", err)
		}
		if got != defaultsAnswer {
			t.Errorf("got %q, want %q", got, defaultsAnswer)
		}
	})

	t.Run("a failed salt read is returned", func(t *testing.T) {
		h := cryptography.NewArgon2id(fixedRandom{})

		_, err := h.Hash([]byte("password"))
		if !errors.Is(err, errShortRead) {
			t.Errorf("got %v, want %v", err, errShortRead)
		}
	})

	t.Run("a hash made with other parameters verifies", func(t *testing.T) {
		tests := []struct {
			name    string
			encoded string
		}{
			{"smaller memory and time", smallAnswer},
			{"time at the cap", "$argon2id$v=19$m=64,t=16,p=1$AQEBAQEBAQEBAQEBAQEBAQ$gpIOwab6QFt0u+1/VioJ9B+mBDa73HhESZNA7hh2DtI"},
			{"salt at the cap", "$argon2id$v=19$m=64,t=1,p=1$" + rawBase64(64) + "$xnDL7M9bfF7fpHRJBTP3ZRtV5KdevE1D+FfcZGIufDo"},
			{"key at the cap", "$argon2id$v=19$m=64,t=1,p=1$AQEBAQEBAQEBAQEBAQEBAQ$M4+skInrHY1TkNjxCZjz3ZivrgJVuynNtZe0qQpmk3WgmHXnigRll6ZJ/xKBl3tMsm/wLpUFZa4BaApymJL9ZA"},
		}

		h := cryptography.NewArgon2id(cryptography.CryptoRandom{})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ok, err := h.Verify([]byte("password"), tt.encoded)
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if !ok {
					t.Errorf("got false, want true")
				}
			})
		}
	})

	t.Run("a malformed hash is refused", func(t *testing.T) {
		tests := []struct {
			name    string
			encoded string
		}{
			{"empty", ""},
			{"wrong algorithm", strings.Replace(defaultsAnswer, "$argon2id$", "$argon2i$", 1)},
			{"wrong version", strings.Replace(defaultsAnswer, "$v=19$", "$v=16$", 1)},
			{"missing field", defaultsAnswer[:strings.LastIndex(defaultsAnswer, "$")]},
			{"unparsable parameters", strings.Replace(defaultsAnswer, "m=19456", "m=x", 1)},
			{"bad salt", strings.Replace(defaultsAnswer, "$AQEB", "$!QEB", 1)},
			{"bad key", strings.Replace(defaultsAnswer, "$FGlX", "$!GlX", 1)},
		}

		h := cryptography.NewArgon2id(cryptography.CryptoRandom{})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := h.Verify([]byte("password"), tt.encoded)
				if !errors.Is(err, cryptography.ErrInvalidPasswordHash) {
					t.Errorf("got %v, want %v", err, cryptography.ErrInvalidPasswordHash)
				}
			})
		}
	})

	t.Run("a hash with out-of-range parameters is refused before it runs", func(t *testing.T) {
		tests := []struct {
			name    string
			encoded string
		}{
			{"empty key", smallAnswer[:strings.LastIndex(smallAnswer, "$")+1]},
			// Fifteen bytes: a key that short is guessable, though argon2 would run.
			{"short key", smallAnswer[:strings.LastIndex(smallAnswer, "$")+1] + "AQEBAQEBAQEBAQEBAQEB"},
			{"short salt", strings.Replace(smallAnswer, "$AQEBAQEBAQEBAQEBAQEBAQ$", "$AQEBAQEBAQEBAQEBAQEB$", 1)},
			{"zero time", strings.Replace(smallAnswer, "t=1", "t=0", 1)},
			{"zero threads", strings.Replace(smallAnswer, "p=1", "p=0", 1)},
			{"time above the cap", strings.Replace(smallAnswer, "t=1", "t=17", 1)},
			// Would allocate 4 TiB if it reached argon2.
			{"memory above the cap", strings.Replace(smallAnswer, "m=64", "m=4294967295", 1)},
			{"salt above the cap", strings.Replace(smallAnswer, "$AQEBAQEBAQEBAQEBAQEBAQ$", "$"+rawBase64(65)+"$", 1)},
			{"key above the cap", smallAnswer[:strings.LastIndex(smallAnswer, "$")+1] + rawBase64(65)},
		}

		h := cryptography.NewArgon2id(cryptography.CryptoRandom{})
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				ok, err := h.Verify([]byte("anything"), tt.encoded)
				if !errors.Is(err, cryptography.ErrInvalidPasswordHash) {
					t.Errorf("got %v, %v, want %v", ok, err, cryptography.ErrInvalidPasswordHash)
				}
			})
		}
	})
}

// BenchmarkArgon2id times one call at the default parameters; each allocates their 19 MiB.
func BenchmarkArgon2id(b *testing.B) {
	password := []byte("correct horse battery staple")

	b.Run("Hash", func(b *testing.B) {
		h := cryptography.NewArgon2id(cryptography.CryptoRandom{})
		b.ReportAllocs()

		for b.Loop() {
			if _, err := h.Hash(password); err != nil {
				b.Fatalf("Hash: %v", err)
			}
		}
	})

	b.Run("Verify", func(b *testing.B) {
		h := cryptography.NewArgon2id(cryptography.CryptoRandom{})
		encoded, err := h.Hash(password)
		if err != nil {
			b.Fatalf("Hash: %v", err)
		}
		b.ReportAllocs()

		for b.Loop() {
			ok, err := h.Verify(password, encoded)
			if err != nil {
				b.Fatalf("Verify: %v", err)
			}
			if !ok {
				b.Fatalf("got false, want true")
			}
		}
	})
}
