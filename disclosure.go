package sd_jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type Disclosure struct {
	Salt  string
	Key   string
	Value any
}

func (d Disclosure) ToString() (string, error) {
	b, err := json.Marshal([]any{d.Salt, d.Key, d.Value})
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (d Disclosure) ToDigest() (string, error) {
	s, err := d.ToString()
	if err != nil {
		return "", err
	}

	b := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func New(key, value string) (*Disclosure, error) {
	salt, err := generateRandomSalt(32)
	if err != nil {
		return nil, err
	}

	return &Disclosure{salt, key, value}, nil
}

func generateRandomSalt(length int) (string, error) {
	salt := make([]byte, length)

	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	saltString := base64.StdEncoding.EncodeToString(salt)
	return saltString, nil
}

func Decode(s string) (*Disclosure, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("1error: %s", err)
	}
	fmt.Println(string(b))

	var a []any
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("2error: %s", err)
	}

	salt, ok := a[0].(string)
	if !ok {
		return nil, fmt.Errorf("3error: %s", err)
	}

	key, ok := a[0].(string)
	if !ok {
		return nil, fmt.Errorf("4error: %s", err)
	}

	return &Disclosure{
		Salt:  salt,
		Key:   key,
		Value: a[2],
	}, nil
}
