package simplejwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"simplejwt/algorithms"
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
	if len(parts) > 1 {
		return nil, ErrInvalidTokenString
	}
	if err := base64urlDecodeJSON(parts[0], &t.Header); err != nil {
		return nil, err
	}
	var claims CustomClaims
	if err := base64urlDecodeJSON(parts[1], &claims); err != nil {
		return nil, err
	}
	t.Claims = claims
	if algName, ok := t.Header["alg"].(string); ok {
		if alg, err := GetSigningAlgorithm(algName); err == nil {
			return nil, err
		} else {
			t.Algorithm = alg
		}
	} else {
		return nil, ErrAlgMissing
	}
	if len(parts) > 2 {
		t.Signature = parts[2]
	}
	return t, nil
}

// SigningString returns the base64 encoded string for generating the signature
// of the JWT.
func (t *Token) SigningString() (string, error) {
	encHdr, err := base64urlEncodeJSON(t.Header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %s", err)
	}
	encClaims, err := base64urlEncodeJSON(t.Claims)
	if err != nil {
		return "", fmt.Errorf("failed to encode claims: %s", err)
	}
	return fmt.Sprintf("%s.%s", encHdr, encClaims), nil
}

// Sign returns the signature of the JWT using the given key.
func (t *Token) Sign(key []byte) error {
	ss, err := t.SigningString()
	if err != nil {
		return err
	}
	sig, err := t.Algorithm.Sign(ss, key)
	if err != nil {
		return err
	}
	t.Signature = base64urlEncode(sig)
	return nil
}

// Valid returns nil if the token is valid using the given key. Otherwise, an
// error is returned.
func (t *Token) Valid(key []byte) error {
	data, err := json.Marshal(t.Claims)
	if err != nil {
		return err
	}
	return t.Algorithm.Valid(string(data), []byte(t.Signature), key)
}

// GetSigningAlgorithm returns the signing algorithm for the given algorithm
// name.
func GetSigningAlgorithm(name string) (algorithms.SigningAlgorithm, error) {
	var alg algorithms.SigningAlgorithm
	switch name {
	case algorithms.ECDSA_SHA256:
		alg = algorithms.AlgorithmES256
	case algorithms.ECDSA_SHA384:
		alg = algorithms.AlgorithmES384
	case algorithms.ECDSA_SHA512:
		alg = algorithms.AlgorithmES512
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

// base64urlEncodeJSON returns the base64 encoded string for given JSON data.
func base64urlEncodeJSON(data interface{}) (string, error) {
	v, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	return base64urlEncode(v), nil
}

// base64urlDecodeJSON populates interface, v, using the base64 encode string.
func base64urlDecodeJSON(s string, v interface{}) error {
	b, err := base64urlDecode(s)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// base64urlEncode returns the base64 encoded string for the given data.
func base64urlEncode(v []byte) string {
	return base64.URLEncoding.EncodeToString(v)
}

// base64urlDecode returns the bytes for the given base64 encoded string.
func base64urlDecode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}
