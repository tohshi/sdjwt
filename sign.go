package sd_jwt

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
)

func Sign(header Header, payload Payload, privateKey crypto.Signer, opts crypto.SignerOpts) (string, error) {
	s := opts.HashFunc().New()

	h, err := header.Encode()
	if err != nil {
		return "", err
	}

	p, err := payload.Encode()
	if err != nil {
		return "", err
	}

	body := h + "." + p

	s.Write([]byte(body))
	hashed := s.Sum(nil)

	b, err := privateKey.Sign(rand.Reader, hashed, opts)
	if err != nil {
		return "", err
	}

	return body + "." + base64.RawURLEncoding.EncodeToString(b), err
}
