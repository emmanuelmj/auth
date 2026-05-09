package auth

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/argon2"
)

type ArgonParameters struct {
	Time    uint32 /* number of iterations */
	Memory  uint32 /* in KB */
	Threads uint8
	KeyLen  uint32
}

/*
Recommended default values
*/
var globalDefaultArgon = ArgonParameters{
	Time:    3,
	Memory:  64 * 1024,
	Threads: 1,
	KeyLen:  32,
}

/*
A function that is not generally recommended to use unless the user have the technically knowledge.
But in case you want to use this, please ensure this is used before any API is validated.
*/
func (a *Auth) DefaultSaltParameters(time uint32, memory uint32, threads uint8, keyLen uint32) error {
	/*
		Some security measures we ensure, this doesn't allow you to shoot yourself in foot completely
	*/
	if time == 0 {
		return fmt.Errorf("%w: time (iterations) cannot be zero", ErrInvalidInput)
	}
	if memory < 32*1024 {
		return fmt.Errorf("%w: memory too low: must be at least 32MB", ErrInvalidInput)
	}
	if threads == 0 {
		return fmt.Errorf("%w: threads cannot be zero", ErrInvalidInput)
	}
	if keyLen < 16 {
		return fmt.Errorf("%w: key length too small: must be at least 16 bytes", ErrInvalidInput)
	}

	a.argonParams.Time = time
	a.argonParams.Memory = memory
	a.argonParams.Threads = threads
	a.argonParams.KeyLen = keyLen

	return nil
}

/*
Although the library holds a lot of control of the functions we are making public.
It does make sense to make a hashing function ΓÇö specifically something that takes a
string and returns an argon2 string public. This is a basic functionality any library should have.

This returns the hashes string and the generated salt.
*/
func (a *Auth) HashPassword(password, salt string) (string, error) {
	passwordBytes := []byte(password)
	if len(a.pepper) > 0 {
		passwordBytes = append(passwordBytes, a.pepper...)
	}
	saltBytes := []byte(salt)
	if len(saltBytes) < 16 {
		return "", fmt.Errorf("%w: salt too short (%d bytes, minimum 16)", ErrInvalidInput, len(saltBytes))
	}

	hash := argon2.IDKey(passwordBytes, saltBytes, a.argonParams.Time, a.argonParams.Memory, a.argonParams.Threads, a.argonParams.KeyLen)

	return hex.EncodeToString(hash), nil
}

func (a *Auth) comparePasswords(password, salt, storedHash string) bool {
	newHash, err := a.HashPassword(password, salt)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(newHash), []byte(storedHash)) == 1
}
