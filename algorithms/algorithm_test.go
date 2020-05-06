package algorithms

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// generated by: $ openssl rsa -in rsa256.key -pubout -outform PEM -out rsa256.key.pub
var testPubKey = `
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEApinL5MnD7r6lU5NLLJn/PFdue0zJ0DZRNAQYq3ZeaDry5VpoI2H7
yLAFGPtPhu+xJgRposqW7kcDTRpSb68BmKxpzqvJpKw3RN2nNSGPhNPf+y3IKx3A
3L6GwiHK1wrBeLNYmYDQu/5R5Gx79a57GlURmT8X5bhPFWIIlInDZ88xNqPmd3ky
ROrTtQvnmOKHlzBoIy903qvNZhO4Y2p+Hb8lvIlVkn16TKVwtk+U7bLpOt3uQRQ/
nWT3RHk5i3/dq8DwwMshOzCwqwVMJfLm4ckV6tYfBWopQd+5VSipwvFvxDUTd9bc
U+wrRyVALdwFoSLfmTdrw114HvZ0ek52ZO1NA0er2nSKgdOPntbTU1TKPZhgQhtq
UAo99M5gOHiF7sJ2jnkGEPJ0BVzSpxbYL/kRjycFP2vV6MQaCle+7uco/R2N05/u
fbU8ZKZfkPg/zq9IhEAszcZ4vJUY7tqFGJwzXiRWX+HaBtgSHxt/iDVDazMGmkdB
oZcWl7/DXw9YDG0/OHwpwscrAOXlYmYJOMspvHUSLhvQbk/sbluWA3v7SX44ZEBI
CSwya1iirDvq9m6f6UnS9rxROU21l8SGVBP2xeICOPHptU8iBan91TWqbUqkUXXm
pa9TbD03zYmj6S4X3aCCeRw57QF03UgAzLvXJzZreLdKwWOmyY3FCBsCAwEAAQ==
-----END RSA PUBLIC KEY-----`

// generated by:
// $ sed -e '/----.* KEY----\|^[[:space:]]*$/d' rsa256.key.pub | \
//   base64 -d |
//   hexdump -v -e '/1 "0x%02x, "' ; echo
var testPubKeyBytes = []byte{
	0x30, 0x82, 0x02, 0x0a, 0x02, 0x82, 0x02, 0x01,
	0x00, 0xa6, 0x29, 0xcb, 0xe4, 0xc9, 0xc3, 0xee,
	0xbe, 0xa5, 0x53, 0x93, 0x4b, 0x2c, 0x99, 0xff,
	0x3c, 0x57, 0x6e, 0x7b, 0x4c, 0xc9, 0xd0, 0x36,
	0x51, 0x34, 0x04, 0x18, 0xab, 0x76, 0x5e, 0x68,
	0x3a, 0xf2, 0xe5, 0x5a, 0x68, 0x23, 0x61, 0xfb,
	0xc8, 0xb0, 0x05, 0x18, 0xfb, 0x4f, 0x86, 0xef,
	0xb1, 0x26, 0x04, 0x69, 0xa2, 0xca, 0x96, 0xee,
	0x47, 0x03, 0x4d, 0x1a, 0x52, 0x6f, 0xaf, 0x01,
	0x98, 0xac, 0x69, 0xce, 0xab, 0xc9, 0xa4, 0xac,
	0x37, 0x44, 0xdd, 0xa7, 0x35, 0x21, 0x8f, 0x84,
	0xd3, 0xdf, 0xfb, 0x2d, 0xc8, 0x2b, 0x1d, 0xc0,
	0xdc, 0xbe, 0x86, 0xc2, 0x21, 0xca, 0xd7, 0x0a,
	0xc1, 0x78, 0xb3, 0x58, 0x99, 0x80, 0xd0, 0xbb,
	0xfe, 0x51, 0xe4, 0x6c, 0x7b, 0xf5, 0xae, 0x7b,
	0x1a, 0x55, 0x11, 0x99, 0x3f, 0x17, 0xe5, 0xb8,
	0x4f, 0x15, 0x62, 0x08, 0x94, 0x89, 0xc3, 0x67,
	0xcf, 0x31, 0x36, 0xa3, 0xe6, 0x77, 0x79, 0x32,
	0x44, 0xea, 0xd3, 0xb5, 0x0b, 0xe7, 0x98, 0xe2,
	0x87, 0x97, 0x30, 0x68, 0x23, 0x2f, 0x74, 0xde,
	0xab, 0xcd, 0x66, 0x13, 0xb8, 0x63, 0x6a, 0x7e,
	0x1d, 0xbf, 0x25, 0xbc, 0x89, 0x55, 0x92, 0x7d,
	0x7a, 0x4c, 0xa5, 0x70, 0xb6, 0x4f, 0x94, 0xed,
	0xb2, 0xe9, 0x3a, 0xdd, 0xee, 0x41, 0x14, 0x3f,
	0x9d, 0x64, 0xf7, 0x44, 0x79, 0x39, 0x8b, 0x7f,
	0xdd, 0xab, 0xc0, 0xf0, 0xc0, 0xcb, 0x21, 0x3b,
	0x30, 0xb0, 0xab, 0x05, 0x4c, 0x25, 0xf2, 0xe6,
	0xe1, 0xc9, 0x15, 0xea, 0xd6, 0x1f, 0x05, 0x6a,
	0x29, 0x41, 0xdf, 0xb9, 0x55, 0x28, 0xa9, 0xc2,
	0xf1, 0x6f, 0xc4, 0x35, 0x13, 0x77, 0xd6, 0xdc,
	0x53, 0xec, 0x2b, 0x47, 0x25, 0x40, 0x2d, 0xdc,
	0x05, 0xa1, 0x22, 0xdf, 0x99, 0x37, 0x6b, 0xc3,
	0x5d, 0x78, 0x1e, 0xf6, 0x74, 0x7a, 0x4e, 0x76,
	0x64, 0xed, 0x4d, 0x03, 0x47, 0xab, 0xda, 0x74,
	0x8a, 0x81, 0xd3, 0x8f, 0x9e, 0xd6, 0xd3, 0x53,
	0x54, 0xca, 0x3d, 0x98, 0x60, 0x42, 0x1b, 0x6a,
	0x50, 0x0a, 0x3d, 0xf4, 0xce, 0x60, 0x38, 0x78,
	0x85, 0xee, 0xc2, 0x76, 0x8e, 0x79, 0x06, 0x10,
	0xf2, 0x74, 0x05, 0x5c, 0xd2, 0xa7, 0x16, 0xd8,
	0x2f, 0xf9, 0x11, 0x8f, 0x27, 0x05, 0x3f, 0x6b,
	0xd5, 0xe8, 0xc4, 0x1a, 0x0a, 0x57, 0xbe, 0xee,
	0xe7, 0x28, 0xfd, 0x1d, 0x8d, 0xd3, 0x9f, 0xee,
	0x7d, 0xb5, 0x3c, 0x64, 0xa6, 0x5f, 0x90, 0xf8,
	0x3f, 0xce, 0xaf, 0x48, 0x84, 0x40, 0x2c, 0xcd,
	0xc6, 0x78, 0xbc, 0x95, 0x18, 0xee, 0xda, 0x85,
	0x18, 0x9c, 0x33, 0x5e, 0x24, 0x56, 0x5f, 0xe1,
	0xda, 0x06, 0xd8, 0x12, 0x1f, 0x1b, 0x7f, 0x88,
	0x35, 0x43, 0x6b, 0x33, 0x06, 0x9a, 0x47, 0x41,
	0xa1, 0x97, 0x16, 0x97, 0xbf, 0xc3, 0x5f, 0x0f,
	0x58, 0x0c, 0x6d, 0x3f, 0x38, 0x7c, 0x29, 0xc2,
	0xc7, 0x2b, 0x00, 0xe5, 0xe5, 0x62, 0x66, 0x09,
	0x38, 0xcb, 0x29, 0xbc, 0x75, 0x12, 0x2e, 0x1b,
	0xd0, 0x6e, 0x4f, 0xec, 0x6e, 0x5b, 0x96, 0x03,
	0x7b, 0xfb, 0x49, 0x7e, 0x38, 0x64, 0x40, 0x48,
	0x09, 0x2c, 0x32, 0x6b, 0x58, 0xa2, 0xac, 0x3b,
	0xea, 0xf6, 0x6e, 0x9f, 0xe9, 0x49, 0xd2, 0xf6,
	0xbc, 0x51, 0x39, 0x4d, 0xb5, 0x97, 0xc4, 0x86,
	0x54, 0x13, 0xf6, 0xc5, 0xe2, 0x02, 0x38, 0xf1,
	0xe9, 0xb5, 0x4f, 0x22, 0x05, 0xa9, 0xfd, 0xd5,
	0x35, 0xaa, 0x6d, 0x4a, 0xa4, 0x51, 0x75, 0xe6,
	0xa5, 0xaf, 0x53, 0x6c, 0x3d, 0x37, 0xcd, 0x89,
	0xa3, 0xe9, 0x2e, 0x17, 0xdd, 0xa0, 0x82, 0x79,
	0x1c, 0x39, 0xed, 0x01, 0x74, 0xdd, 0x48, 0x00,
	0xcc, 0xbb, 0xd7, 0x27, 0x36, 0x6b, 0x78, 0xb7,
	0x4a, 0xc1, 0x63, 0xa6, 0xc9, 0x8d, 0xc5, 0x08,
	0x1b, 0x02, 0x03, 0x01, 0x00, 0x01,
}

func TestPemBlock(t *testing.T) {
	b := pemBlock([]byte(testPubKey))
	require.NotNil(t, b)
	require.NotEqual(t, []byte(""), b)
	require.Equal(t, testPubKeyBytes, b)
}

func TestBigIntToBytes(t *testing.T) {
	by := byte(0x01)
	sz := 4
	bigInt := big.NewInt(int64(by))
	expected := make([]byte, sz)
	expected[sz-1] = by
	actual := bigIntToBytes(bigInt, sz)
	require.Equal(t, expected, actual)
}
