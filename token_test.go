package simplejwt

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/crossedbot/simplejwt/algorithms"

	"github.com/stretchr/testify/require"
)

// generated by: $ openssl genrsa -out rsa2048.key 2048
var testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxlxFs+nTK+AQ4wvvfyNz+KEZ7VFsLh88gVuR4L70wmoI1IYm
8cvO5eQPgbnZNQWFVMMCGCMrcoa9tXt9ASf6KxY8gET5kPR49Y42FPLyBvqbOB6K
AtA0wZY9JgLuL9C0Ij1tu2R5nHU3EmkL0U4ud9L2CJlCHSwkn6LiG6Y/NUYDfF3v
c9Regp7uPXN4Lyg59XRnRPRfYrUgEvlb2YfGSchXV11KIz7o8SUvZtX2Kt1NNIx+
2H/uuBC30wFtAR7iRNxSmukj25N3obNREYXIw3/KWs+G/bqQxa7bc+FA2NhjUBFn
uliuHDKWnpTzxRFF3f1Wd68cp88esis94wCamQIDAQABAoIBAF850OSMLip0COdW
xYT9miEUBgReAFcr+7oGIcQJKCtlCBQuyudtdkf68k7Oz62aluWYMJsx1xvF/7Du
NZamgHzK0gSqGD00gBUyTlhEQViEWpvYXVz4YztEStrCsWIXCUMexl0d4RvxUZzu
/RNgOwKfLin2mTy0Amj4ox+u8c06lKyFCIq3sBRkP9mxLEXDf92xikfdKFlARWX6
FT6awgbNtQcdllyc6FCuBhIczt3+4muwRw+q2UD/N0hseZS6aHyYDy/TXbU1WCnN
EanlY7nL9E6KxviN1ZNOHc/fhwD0TtEyNC7AyTbrj8lCQ9TMNGNX3tg6WcV5tZfK
u15rrGECgYEA7XvVH7hDspcrgUIkaBeVXuHltBCxQxZDD9323kkbB9rxLXJMZMP7
R0zlsEtw9u8rJq21hllQBYAzx9n93iccSykoA7Md/Vp20Q/6dfFJrFqf4nN+AktP
aZd1kB9K1m+MPyMEBR0ObOpbJhywI00Jv3uNqDzkDpCxbC6IJshF2bUCgYEA1dOK
UPaewg0aHT3TtZIZdS18cPWMWzWC0eCN0Kr3jXP4BXvq0extZe/mt8lu+yRYZfC1
yGBRHjCmZvwGx7fRwnPznUOF+aIjhfKWvA1AUAlA6XY5b/hGStOlv6uj8rs5bbRC
5dpsDiFqSWUvz3vaeE/Ahrua80XXe/xFR592+9UCgYEAp3a5NSL06gzbqsx/a7+l
n0Dgf/d9aHdcVuYI3XrjyshDZe7BnBTvLro1BfpM8HR7E01PQivc1+Qtn3JDKNKf
iwi8pM88CJowSwBfd6fscdN+B2u1odyFZUpepoDKfygt15/Th9+Teo5QNDHqqxn6
E8MGg2pcz0CNPGIbtG1phDkCgYEAknwOOLMLRcM2DaxKegwxto3Hv5boZZ++FEvy
u240k0pMMm2XC+MdewUjmOq9Rf27NXL3BeO+DqGjjc/AUVgDsmQ/E5Crmr3R+jSb
wQ6O7YW5W3brmGKMvTxLQ4ixk1th117zqYW+GtwXdVqFq22c2GlCasrhNyG0orLL
P2rmV1UCgYEAqjEd5VDALclr+NGpvfFPLfxq6WJD1YgGdLYlEkHY2rz4EB2DBHg6
DD/a0rBujuyf9SBL0riDHuRMQPFDFQyFZ31iaoWCEzKn5/LwxSdxEORpK/X6Q3gQ
K2oVTJPFwtdcRZOXAEhLgknv4xJU9xC45SzoYiBm/igyy3sJJ3SxHxQ=
-----END RSA PRIVATE KEY-----`

// generated by: $ openssl rsa -in rsa2048.key -outform PEM -pubout -out rsa2048.key.pub
var testPublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxlxFs+nTK+AQ4wvvfyNz
+KEZ7VFsLh88gVuR4L70wmoI1IYm8cvO5eQPgbnZNQWFVMMCGCMrcoa9tXt9ASf6
KxY8gET5kPR49Y42FPLyBvqbOB6KAtA0wZY9JgLuL9C0Ij1tu2R5nHU3EmkL0U4u
d9L2CJlCHSwkn6LiG6Y/NUYDfF3vc9Regp7uPXN4Lyg59XRnRPRfYrUgEvlb2YfG
SchXV11KIz7o8SUvZtX2Kt1NNIx+2H/uuBC30wFtAR7iRNxSmukj25N3obNREYXI
w3/KWs+G/bqQxa7bc+FA2NhjUBFnuliuHDKWnpTzxRFF3f1Wd68cp88esis94wCa
mQIDAQAB
-----END PUBLIC KEY-----`

func TestParse(t *testing.T) {
	claims := RegisteredClaims{
		Issuer:         "issuer",
		Subject:        "subject",
		Audience:       "audience",
		ExpirationTime: 1588732200,
		NotBefore:      1588473060,
		IssuedAt:       1588473060,
	}
	token := New(claims, algorithms.AlgorithmRS256)
	_, err := token.Sign([]byte(testPrivateKey))
	require.Nil(t, err)
	jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwiYXVkIjoiYXVkaWVuY2UiLCJleHAiOjE1ODg3MzIyMDAsIm5iZiI6MTU4ODQ3MzA2MCwiaWF0IjoxNTg4NDczMDYwfQ.swBeSSjVDu1o_qQELCQcYlHE-te0BxAKCAH1GPwBHRc3ko_RJtcklbR5cYIXdtH-xGPkYuU36KQgjH7wBJkRwbc-wfKPiWM_WwkdMU42GXP6L1IIhn2K43_Rx0mB_hwbSlemQYZkSe-h589CpSqQZJTwYhEznJJYXe9Ymd_1n8deZHOE8qst_0eJ_oGGyUE1_Dr6FzjsLIuK7KVVyuzfQeePVZHfsKRTw_CqxV8yIA7y5g7_q_dlD0pF_fGNpOB3_qEK31wStLi9Pzna93cALOkS07xclswyNsOwX-2YqxfACGyZIsyyUU_L-DvYAhDxQw5y3CBbtX7JVzoeSOQAhQ"
	actual, err := Parse(jwt)
	require.Nil(t, err)
	require.Equal(t, token.Data, actual.Data)
	require.Equal(t, token.Signature, actual.Signature)
}

func TestGetSigningAlgorithmECDSA(t *testing.T) {
	alg, err := GetSigningAlgorithm(algorithms.ECDSA_SHA256)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmEC256, alg)
	alg, err = GetSigningAlgorithm(algorithms.ECDSA_SHA384)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmEC384, alg)
	alg, err = GetSigningAlgorithm(algorithms.ECDSA_SHA512)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmEC512, alg)
}

func TestGetSigningAlgorithmHMAC(t *testing.T) {
	alg, err := GetSigningAlgorithm(algorithms.HMAC_SHA256)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmHS256, alg)
	alg, err = GetSigningAlgorithm(algorithms.HMAC_SHA384)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmHS384, alg)
	alg, err = GetSigningAlgorithm(algorithms.HMAC_SHA512)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmHS512, alg)
}

func TestGetSigningAlgorithmRSA(t *testing.T) {
	alg, err := GetSigningAlgorithm(algorithms.RSA_SHA256)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmRS256, alg)
	alg, err = GetSigningAlgorithm(algorithms.RSA_SHA384)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmRS384, alg)
	alg, err = GetSigningAlgorithm(algorithms.RSA_SHA512)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmRS512, alg)
}

func TestGetSigningAlgorithmRSAPSS(t *testing.T) {
	alg, err := GetSigningAlgorithm(algorithms.RSAPSS_SHA256)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmPS256, alg)
	alg, err = GetSigningAlgorithm(algorithms.RSAPSS_SHA384)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmPS384, alg)
	alg, err = GetSigningAlgorithm(algorithms.RSAPSS_SHA512)
	require.Nil(t, err)
	require.Equal(t, algorithms.AlgorithmPS512, alg)
}

func TestGetSigningAlgorithm(t *testing.T) {
	TestGetSigningAlgorithmECDSA(t)
	TestGetSigningAlgorithmHMAC(t)
	TestGetSigningAlgorithmRSA(t)
	TestGetSigningAlgorithmRSAPSS(t)
}

func TestTokenSigningString(t *testing.T) {
	expected := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJzdWJqZWN0IiwiYXVkIjoiYXVkaWVuY2UiLCJleHAiOjE1ODg3MzIyMDAsIm5iZiI6MTU4ODQ3MzA2MCwiaWF0IjoxNTg4NDczMDYwfQ"
	claims := RegisteredClaims{
		Issuer:         "issuer",
		Subject:        "subject",
		Audience:       "audience",
		ExpirationTime: 1588732200,
		NotBefore:      1588473060,
		IssuedAt:       1588473060,
	}
	token := New(claims, algorithms.AlgorithmRS256)
	actual, err := token.SigningString()
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestTokenSign(t *testing.T) {
	sig := "swBeSSjVDu1o_qQELCQcYlHE-te0BxAKCAH1GPwBHRc3ko_RJtcklbR5cYIXdtH-xGPkYuU36KQgjH7wBJkRwbc-wfKPiWM_WwkdMU42GXP6L1IIhn2K43_Rx0mB_hwbSlemQYZkSe-h589CpSqQZJTwYhEznJJYXe9Ymd_1n8deZHOE8qst_0eJ_oGGyUE1_Dr6FzjsLIuK7KVVyuzfQeePVZHfsKRTw_CqxV8yIA7y5g7_q_dlD0pF_fGNpOB3_qEK31wStLi9Pzna93cALOkS07xclswyNsOwX-2YqxfACGyZIsyyUU_L-DvYAhDxQw5y3CBbtX7JVzoeSOQAhQ"
	claims := RegisteredClaims{
		Issuer:         "issuer",
		Subject:        "subject",
		Audience:       "audience",
		ExpirationTime: 1588732200,
		NotBefore:      1588473060,
		IssuedAt:       1588473060,
	}
	token := New(claims, algorithms.AlgorithmRS256)
	_, err := token.Sign([]byte(testPrivateKey))
	require.Nil(t, err)
	require.Equal(t, sig, token.Signature)
}

func TestTokenValid(t *testing.T) {
	claims := RegisteredClaims{
		Issuer:         "issuer",
		Subject:        "subject",
		Audience:       "audience",
		ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
		NotBefore:      time.Now().Add(-1 * time.Hour).Unix(),
		IssuedAt:       time.Now().Unix(),
	}
	token := New(claims, algorithms.AlgorithmRS256)
	_, err := token.Sign([]byte(testPrivateKey))
	require.Nil(t, err)
	err = token.Valid([]byte(testPublicKey))
	require.Nil(t, err)
}

func TestBase64urlEncode(t *testing.T) {
	b := []byte("test string")
	expected := base64.URLEncoding.EncodeToString(b)
	actual := base64urlEncode(b)
	require.Equal(t, expected, actual)
}

func TestBase64urlDecode(t *testing.T) {
	expected := []byte("test string")
	encStr := base64.URLEncoding.EncodeToString(expected)
	actual, err := base64urlDecode(encStr)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestEncode(t *testing.T) {
	b := []byte("test string")
	expected := "dGVzdCBzdHJpbmc"
	actual := encode(b)
	require.Equal(t, expected, actual)
}

func TestDecode(t *testing.T) {
	enc := "dGVzdCBzdHJpbmc"
	expected := []byte("test string")
	actual, err := decode(enc)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestEncodeJSON(t *testing.T) {
	type V struct {
		I   int    `json:"i"`
		Str string `json:"str"`
	}
	data := V{I: 10, Str: "string"}
	b, err := json.Marshal(data)
	require.Nil(t, err)
	require.NotNil(t, b)
	expected := strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	actual, err := encodeJSON(data)
	require.Nil(t, err)
	require.Equal(t, expected, actual)
}

func TestDecodeJSON(t *testing.T) {
	type V struct {
		I   int    `json:"i"`
		Str string `json:"str"`
	}
	data := V{I: 10, Str: "string"}
	b, err := json.Marshal(data)
	require.Nil(t, err)
	require.NotNil(t, b)
	enc := strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
	var v V
	err = decodeJSON(enc, &v)
	require.Nil(t, err)
	require.Equal(t, data, v)
}
