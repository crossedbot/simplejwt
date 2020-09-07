package simplejwt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidExpirationTime(t *testing.T) {
	now := int64(1596844800)
	exp := int64(1596758400)
	require.False(t, validExpirationTime(exp, now))
	exp = 0
	require.True(t, validExpirationTime(exp, now))
	exp = 1596931200
	require.True(t, validExpirationTime(exp, now))
	exp = now
	require.True(t, validExpirationTime(exp, now))
}

func TestValidNotBefore(t *testing.T) {
	now := int64(1596844800)
	nbf := int64(1596758400)
	require.False(t, validNotBefore(nbf, now))
	nbf = 0
	require.True(t, validNotBefore(nbf, now))
	nbf = 1596931200
	require.True(t, validNotBefore(nbf, now))
	nbf = now
	require.True(t, validNotBefore(nbf, now))
}

func TestIssuedAt(t *testing.T) {
	now := int64(1596844800)
	iat := int64(1596758400)
	require.False(t, validNotBefore(iat, now))
	iat = 0
	require.True(t, validNotBefore(iat, now))
	iat = 1596931200
	require.True(t, validNotBefore(iat, now))
	iat = now
	require.True(t, validNotBefore(iat, now))
}

func TestI64(t *testing.T) {
	expected := int64(123)
	f := 123.456
	i := 123
	n := json.Number("123")
	require.Equal(t, expected, i64(expected))
	require.Equal(t, expected, i64(f))
	require.Equal(t, expected, i64(i))
	require.Equal(t, expected, i64(n))
}

func TestCustomClaimsValid(t *testing.T) {
	now := int64(1596844800)
	cc := make(CustomClaims)
	cc["exp"] = int64(1596758400)
	cc["nbf"] = int64(0)
	cc["iat"] = int64(0)
	require.Equal(t, ErrInvalidExpirationTime, cc.Valid(now))
	cc["exp"] = int64(0)
	cc["nbf"] = int64(1596758400)
	cc["iat"] = int64(0)
	require.Equal(t, ErrInvalidNotBefore, cc.Valid(now))
	cc["exp"] = int64(0)
	cc["nbf"] = int64(0)
	cc["iat"] = int64(1596758400)
	require.Equal(t, ErrInvalidIssuedAt, cc.Valid(now))
	cc["exp"] = int64(0)
	cc["nbf"] = int64(0)
	cc["iat"] = int64(0)
	require.Nil(t, cc.Valid(now))
	cc["exp"] = int64(1596931200)
	cc["nbf"] = int64(1596931200)
	cc["iat"] = int64(1596931200)
	require.Nil(t, cc.Valid(now))
}

func TestRegisteredClaimsValid(t *testing.T) {
	now := int64(1596844800)
	rc := RegisteredClaims{}
	rc.ExpirationTime = int64(1596758400)
	rc.NotBefore = int64(0)
	rc.IssuedAt = int64(0)
	require.Equal(t, ErrInvalidExpirationTime, rc.Valid(now))
	rc.ExpirationTime = int64(0)
	rc.NotBefore = int64(1596758400)
	rc.IssuedAt = int64(0)
	require.Equal(t, ErrInvalidNotBefore, rc.Valid(now))
	rc.ExpirationTime = int64(0)
	rc.NotBefore = int64(0)
	rc.IssuedAt = int64(1596758400)
	require.Equal(t, ErrInvalidIssuedAt, rc.Valid(now))
	rc.ExpirationTime = int64(0)
	rc.NotBefore = int64(0)
	rc.IssuedAt = int64(0)
	require.Nil(t, rc.Valid(now))
	rc.ExpirationTime = int64(1596931200)
	rc.NotBefore = int64(1596931200)
	rc.IssuedAt = int64(1596931200)
	require.Nil(t, rc.Valid(now))
}
