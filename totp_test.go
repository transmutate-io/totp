package totp

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func init() { timeNow = func() time.Time { return time.Time{} } }

func TestURL(t *testing.T) {
	// test unhappy paths
	testUrls := []struct {
		url    string
		expErr int
	}{
		{"not-otpauth://totp", InvalidScheme},
		{"otpauth://xxxxxxx", InvalidOtpType},
		{"otpauth://totp/", MissingLabel},
		{"otpauth://totp/somedomain.com?algorithm=xxxx", InvalidAlgorithm},
		{"otpauth://totp/somedomain.com?digits=xxxxx", InvalidDigits},
		{"otpauth://totp/somedomain.com?digits=7", InvalidDigits},
		{"otpauth://totp/somedomain.com?period=xxxxx", InvalidPeriod},
		{"otpauth://totp/somedomain.com?period=0", InvalidPeriod},
		{"otpauth://totp/somedomain.com?", MissingKey},
		{"otpauth://totp/somedomain.com?secret=!D!2!R!Q!K!O!Z!W", Base32Decoding},
	}
	for _, tu := range testUrls {
		_, err := ParseURL(tu.url)
		require.Errorf(t, err, "expecting an error for %s", tu.url)
		require.IsType(t, &Error{}, err, "got the wrong error type")
		require.Equalf(t, tu.expErr, err.(*Error).Err, "expecting a different error. got: %#+v", err)
	}

	// generate a new url
	k := NewURL("somedomain.com (username)", "somedomain.com", NewSecret([]byte("AAAAAAAAAA")))
	eu, err := url.Parse("otpauth://totp/somedomain.com (username)?secret=IFAUCQKBIFAUCQKB&issuer=somedomain.com")
	require.NoError(t, err, "unexpected error")
	u, err := url.Parse(k.String())
	require.NoError(t, err, "unexpected error")
	require.Equal(t, eu.Scheme, u.Scheme, "scheme mismatch")
	require.Equal(t, eu.Host, u.Host, "host mismatch")
	require.Equal(t, eu.Path, u.Path, "path mismatch")
	require.Equal(t, eu.Query(), u.Query(), "query string mismatch")
}

func TestSecret(t *testing.T) {
	s := NewSecret([]byte("AAAAAAAAAA"))
	counter := 1000
	codes := []string{
		"780613", "657435", "836095", "738199",
		"293353", "684319", "243321", "199937",
		"011790", "774933", "314021", "096305",
	}
	for i, c := range codes {
		require.True(t, s.CheckCounterCode(uint(counter+i), c), "code mismatch")
	}
}
