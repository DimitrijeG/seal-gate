package cryptography

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidPasswordHash reports a stored hash that is not argon2id in PHC form, or whose parameters are out of range.
var ErrInvalidPasswordHash = errors.New("cryptography: invalid password hash")

const (
	// Memory is in KiB, as argon2 takes it; time is the number of passes over that memory.
	argon2Memory  = 19 << 10
	argon2Time    = 2
	argon2Threads = 1
	argon2SaltLen = 16
	argon2KeyLen  = 32
	// Below this a stored salt or key is too short to trust; an empty key would crash argon2.
	argon2MinLen = 16
	// Caps on what a stored hash may ask for, so a corrupt record cannot cost unbounded memory or time.
	argon2MaxMemory = 256 << 10
	argon2MaxTime   = 16
)

// Argon2id hashes passwords with argon2id, encoded as PHC strings that carry their own parameters.
type Argon2id struct {
	random Random
}

// NewArgon2id returns an Argon2id that draws each salt from random.
func NewArgon2id(random Random) *Argon2id {
	return &Argon2id{random: random}
}

// Hash returns password's hash under a new salt and the default parameters.
func (a *Argon2id) Hash(password []byte) (string, error) {
	salt, err := a.random.Bytes(argon2SaltLen)
	if err != nil {
		return "", fmt.Errorf("cryptography: %w", err)
	}
	key := argon2.IDKey(password, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify reports whether password matches encoded, deriving with encoded's own parameters; a malformed one is ErrInvalidPasswordHash.
func (a *Argon2id) Verify(password []byte, encoded string) (bool, error) {
	stored, err := parseArgon2id(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey(password, stored.salt, stored.time, stored.memory, stored.threads, uint32(len(stored.key)))
	return subtle.ConstantTimeCompare(key, stored.key) == 1, nil
}

// argon2idHash is a parsed PHC string: what Verify derives with, and the key it must match.
type argon2idHash struct {
	memory, time uint32
	threads      uint8
	salt, key    []byte
}

func parseArgon2id(encoded string) (argon2idHash, error) {
	fields := strings.Split(encoded, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" || fields[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return argon2idHash{}, ErrInvalidPasswordHash
	}

	var h argon2idHash
	_, err := fmt.Sscanf(fields[3], "m=%d,t=%d,p=%d", &h.memory, &h.time, &h.threads)
	// Printed back and compared, so trailing text, signs and leading zeros are refused too.
	if err != nil || fields[3] != fmt.Sprintf("m=%d,t=%d,p=%d", h.memory, h.time, h.threads) {
		return argon2idHash{}, ErrInvalidPasswordHash
	}

	if h.salt, err = base64.RawStdEncoding.DecodeString(fields[4]); err != nil {
		return argon2idHash{}, ErrInvalidPasswordHash
	}
	if h.key, err = base64.RawStdEncoding.DecodeString(fields[5]); err != nil {
		return argon2idHash{}, ErrInvalidPasswordHash
	}
	if !h.inRange() {
		return argon2idHash{}, ErrInvalidPasswordHash
	}
	return h, nil
}

// inRange refuses what argon2 would panic on (zero time or threads) and what would cost unbounded memory or time.
func (h argon2idHash) inRange() bool {
	return h.time >= 1 && h.time <= argon2MaxTime &&
		h.memory <= argon2MaxMemory &&
		h.threads >= 1 &&
		len(h.salt) >= argon2MinLen &&
		len(h.key) >= argon2MinLen
}
