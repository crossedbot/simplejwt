package simplejwt

import (
	"encoding/json"
	"errors"
)

var (
	ErrInvalidExpirationTime = errors.New("invalid expiration time")
	ErrInvalidNotBefore      = errors.New("invalid not before")
	ErrInvalidIssuedAt       = errors.New("invalid issued at")
)

// Claims represents the a claims set.
type Claims interface {
	Valid(int64) error
	Get(key string) interface{}
}

// CustomClaims represents a custom claims set.
type CustomClaims map[string]interface{}

// Valid returns an error if the CustomClaims object is not valid. Otherwise nil
// is returned; indicating the claims set is valid.
func (cc CustomClaims) Valid(t int64) error {
	if exp := i64(cc["exp"]); exp > 0 {
		if !validExpirationTime(exp, t) {
			return ErrInvalidExpirationTime
		}
	}
	if nbf := i64(cc["nbf"]); nbf > 0 {
		if !validNotBefore(nbf, t) {
			return ErrInvalidNotBefore
		}
	}
	if iat := i64(cc["iat"]); iat > 0 {
		if !validIssuedAt(iat, t) {
			return ErrInvalidIssuedAt
		}
	}
	return nil
}

func (cc CustomClaims) Get(key string) (value interface{}) {
	if cc != nil {
		value = cc[key]
	}
	return
}

// RegisteredClaims implements a claims set using the registered (standard)
// claims according to the IANA "JSON Web Token Claims" registry.
type RegisteredClaims struct {
	Issuer         string `json:"iss,omitempty"`
	Subject        string `json:"sub,omitempty"`
	Audience       string `json:"aud,omitempty"`
	ExpirationTime int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	IssuedAt       int64  `json:"iat,omitempty"`
	JWTID          string `json:"jti,omitempty"`
}

// Valid returns an error if the RegisteredClaims object is not valid. Otherwise
// nil is returned; indicating the claims set is valid.
func (rc RegisteredClaims) Valid(t int64) error {
	if !validExpirationTime(rc.ExpirationTime, t) {
		return ErrInvalidExpirationTime
	}
	if !validNotBefore(rc.NotBefore, t) {
		return ErrInvalidNotBefore
	}
	if !validIssuedAt(rc.IssuedAt, t) {
		return ErrInvalidIssuedAt
	}
	return nil
}

func (rc RegisteredClaims) Get(key string) (value interface{}) {
	switch key {
	case "iss":
		value = rc.Issuer
	case "sub":
		value = rc.Subject
	case "aud":
		value = rc.Audience
	case "exp":
		value = rc.ExpirationTime
	case "nbf":
		value = rc.NotBefore
	case "iat":
		value = rc.IssuedAt
	case "jti":
		value = rc.JWTID
	}
	return
}

// validExpirationTime returns true if the expiration time is valid or zero.
func validExpirationTime(exp, t int64) bool {
	return 0 == exp || t <= exp
}

// validNotBefore returns true if the not before datetime is valid or zero.
func validNotBefore(nbf, t int64) bool {
	return 0 == nbf || t >= nbf
}

// validIssuedAt returns true if the issued at datetime is valid or zero.
func validIssuedAt(iat, t int64) bool {
	return 0 == iat || t >= iat
}

// i64 returns the int64 representation of interface i. If the interface is not
// a datatype compatible with int64, 0 is returned.
func i64(i interface{}) int64 {
	switch v := i.(type) {
	case int64:
		return int64(v)
	case float64:
		return int64(v)
	case int:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	}
	return 0
}
