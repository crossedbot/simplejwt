package simplejwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/crossedbot/simplejwt/algorithms"
)

var (
	ErrInvalidTokenString = errors.New("invalid token string")
	ErrAlgMissing         = errors.New("JOSE header is missing alg field")
	ErrUnknownAlg         = errors.New("unknown signing method")
)

// JOSEHeader represents the JOSE header of a JWT. It is common, that only the
// typ and alg fields are set; identifying the algorithm used in generating the
// JWT's signature.
type JOSEHeader map[string]interface{}

// Token represents a JSON Web Token (JWT).
type Token struct {
	Header    JOSEHeader
	Claims    Claims
	Data      string
	Signature string
	Algorithm algorithms.SigningAlgorithm
}

// NewToken returns a new JWT instance.
func New(claims Claims, alg algorithms.SigningAlgorithm) *Token {
	return &Token{
		Header:    JOSEHeader{"typ": "JWT", "alg": alg.Name()},
		Claims:    claims,
		Algorithm: alg,
	}
}

// Parse returns a token parsed from the given token string.
func Parse(tokenStr string) (*Token, error) {
	t := new(Token)
	parts := strings.Split(tokenStr, ".")
	if len(parts) < 2 {
		return nil, ErrInvalidTokenString
	}
	if err := decodeJSON(parts[0], &t.Header); err != nil {
		return nil, err
	}
	var claims CustomClaims
	if err := decodeJSON(parts[1], &claims); err != nil {
		return nil, err
	}
	t.Claims = claims
	if algName, ok := t.Header["alg"].(string); ok {
		if alg, err := GetSigningAlgorithm(algName); err != nil {
			return nil, err
		} else {
			t.Algorithm = alg
		}
	} else {
		return nil, ErrAlgMissing
	}
	t.Data = strings.Join(parts[:2], ".")
	if len(parts) > 2 {
		t.Signature = parts[2]
	}
	return t, nil
}

// SigningString returns the base64 encoded string for generating the signature
// of the JWT.
func (t *Token) SigningString() (string, error) {
	encHdr, err := encodeJSON(t.Header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %s", err)
	}
	encClaims, err := encodeJSON(t.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to encode claims: %s", err)
	}
	return fmt.Sprintf("%s.%s", encHdr, encClaims), nil
}

// Sign returns the signature of the JWT using the given key.
func (t *Token) Sign(key []byte) (string, error) {
	var err error
	t.Data, err = t.SigningString()
	if err != nil {
		return "", err
	}
	sig, err := t.Algorithm.Sign(t.Data, key)
	if err != nil {
		return "", err
	}
	t.Signature = encode(sig)
	return fmt.Sprintf("%s.%s", t.Data, t.Signature), nil
}

// Valid returns nil if the token is valid using the given key. Otherwise, an
// error is returned.
func (t *Token) Valid(key []byte) error {
	if err := t.Claims.Valid(time.Now().Unix()); err != nil {
		return err
	}
	sig, err := decode(t.Signature)
	if err != nil {
		return err
	}
	return t.Algorithm.Valid(t.Data, sig, key)
}

// GetSigningAlgorithm returns the signing algorithm for the given algorithm
// name.
func GetSigningAlgorithm(name string) (algorithms.SigningAlgorithm, error) {
	var alg algorithms.SigningAlgorithm
	switch name {
	case algorithms.ECDSA_SHA256:
		alg = algorithms.AlgorithmEC256
	case algorithms.ECDSA_SHA384:
		alg = algorithms.AlgorithmEC384
	case algorithms.ECDSA_SHA512:
		alg = algorithms.AlgorithmEC512
	case algorithms.HMAC_SHA256:
		alg = algorithms.AlgorithmHS256
	case algorithms.HMAC_SHA384:
		alg = algorithms.AlgorithmHS384
	case algorithms.HMAC_SHA512:
		alg = algorithms.AlgorithmHS512
	case algorithms.RSA_SHA256:
		alg = algorithms.AlgorithmRS256
	case algorithms.RSA_SHA384:
		alg = algorithms.AlgorithmRS384
	case algorithms.RSA_SHA512:
		alg = algorithms.AlgorithmRS512
	case algorithms.RSAPSS_SHA256:
		alg = algorithms.AlgorithmPS256
	case algorithms.RSAPSS_SHA384:
		alg = algorithms.AlgorithmPS384
	case algorithms.RSAPSS_SHA512:
		alg = algorithms.AlgorithmPS512
	default:
		return nil, fmt.Errorf("%s: %s", ErrUnknownAlg, alg)
	}
	return alg, nil
}

// base64urlEncode returns the base64 encoded string for the given data.
func base64urlEncode(v []byte) string {
	return base64.URLEncoding.EncodeToString(v)
}

// base64urlDecode returns the bytes for the given base64 encoded string.
func base64urlDecode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

// encode encodes the given data as a base64 URL encoded string without the
// padding.
func encode(v []byte) string {
	return strings.TrimRight(base64urlEncode(v), "=")
}

// decode decodes the given string; assuming it is a base64 URL encoded string
// without padding.
func decode(s string) ([]byte, error) {
	if l := len(s) % 4; l > 0 {
		padding := strings.Repeat("=", 4-l)
		s = fmt.Sprintf("%s%s", s, padding)
	}
	return base64urlDecode(s)
}

// encodeJSON returns the base64 encoded string for given JSON data.
func encodeJSON(data interface{}) (string, error) {
	v, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return encode(v), nil
}

// decodeJSON populates interface, v, using the base64 encode string.
func decodeJSON(s string, v interface{}) error {
	b, err := decode(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
