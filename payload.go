package sd_jwt

import (
	"encoding/base64"
	"encoding/json"
)

type Payload struct {
	Disclosures []Disclosure
	Claims      map[string]any
}

func NewPayload() *Payload {
	return &Payload{
		Disclosures: []Disclosure{},
		Claims:      map[string]any{},
	}
}

func (p *Payload) AddDisclosure(d Disclosure) {
	p.Disclosures = append(p.Disclosures, d)
}

func (p *Payload) SetClaim(key string, value any) {
	p.Claims[key] = value
}

func (p *Payload) Encode() (string, error) {
	payload := map[string]any{}
	for k, v := range p.Claims {
		payload[k] = v
	}

	sd := []string{}
	for _, d := range p.Disclosures {
		s, _ := d.ToDigest()
		sd = append(sd, s)
	}
	payload["_sd"] = sd

	b, err := json.Marshal(&payload)
	if err != nil {
		return "", err

	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
