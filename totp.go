package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Algorithms strings
const (
	AlgorithmSha1   = "sha1" // only algorithm supported by google authenticator
	AlgorithmSha256 = "sha256"
	AlgorithmSha512 = "sha512"
)

// Algorithms contains the available algos
var Algorithms = map[string]func() hash.Hash{
	AlgorithmSha1:   sha1.New,
	AlgorithmSha256: sha256.New,
	AlgorithmSha512: sha512.New,
}

// Common defaults for TOTP
const (
	DefaultDigits    = 6                // 6 digit code.
	DefaultAlgorithm = AlgorithmSha1    // SHA1 is the only supported.
	DefaultPeriod    = 30 * time.Second // Default period is 30 seconds.
	KeyLength        = 10               //default key length is 10 bytes
)

var timeNow = time.Now

// hashing and truncation
func hashTruncateInt(algo func() hash.Hash, key []byte, counter uint) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(counter))
	hm := hmac.New(algo, key)
	if _, err := hm.Write(b); err != nil {
		panic(err)
	}
	b = hm.Sum(nil)
	ofs := int(b[19] & 0xf)
	c := make([]byte, 4)
	copy(c, b[ofs:ofs+4])
	c[0] = c[0] & 0x7f
	return c
}

// TimeToCounter converts a time.Time to a counter
func TimeToCounter(t time.Time, p time.Duration) uint { return uint(t.Unix()) / uint(p.Seconds()) }

// CounterNow returns the current counter for the default period
func CounterNow() uint { return TimeToCounter(timeNow(), DefaultPeriod) }

// CounterCodeFull returns the code, using algo and digits
func CounterCodeFull(algo func() hash.Hash, key []byte, counter uint, digits int) string {
	c := hashTruncateInt(algo, key, counter)
	i := int(binary.BigEndian.Uint32(c)) % int(math.Pow10(int(digits)))
	f := fmt.Sprintf("%%.%dd", digits)
	return fmt.Sprintf(f, i)
}

// CheckCounterCodeFull checks the code, using algo and digits
func CheckCounterCodeFull(algo func() hash.Hash, key []byte, counter uint, digits int, code string) bool {
	return CounterCodeFull(algo, key, counter, digits) == code
}

// CounterCode returns the code, using defaults
func CounterCode(key []byte, counter uint) string {
	return CounterCodeFull(Algorithms[DefaultAlgorithm], key, counter, DefaultDigits)
}

// CheckCounterCode checks the code, using defaults
func CheckCounterCode(key []byte, counter uint, code string) bool {
	return CounterCode(key, counter) == code
}

// CounterCodeNow returns the current code, using defaults
func CounterCodeNow(key []byte) string { return CounterCode(key, CounterNow()) }

// CheckCounterCodeNow checks the current code, using defaults
func CheckCounterCodeNow(key []byte, code string) bool {
	return CounterCodeNow(key) == code
}

// Secret represents a TOTP secret
type Secret struct {
	Key    []byte
	Digits uint
	Period time.Duration
	// fields below are ignored by Google Authenticator. Always use sha1
	Algorithm string
}

// GenerateSecret returns a new *Secret with defaults set and a new key
func GenerateSecret() (*Secret, error) {
	b := make([]byte, KeyLength)
	if n, err := rand.Read(b); err != nil {
		return nil, NewError(CantReadRandom, err.Error())
	} else if n != KeyLength {
		return nil, NewError(NotEnoughRandom)
	}
	return NewSecret(b), nil
}

// NewSecret returns a new *Secret with defaults set
func NewSecret(key []byte) *Secret {
	return &Secret{
		Digits:    DefaultDigits,
		Algorithm: DefaultAlgorithm,
		Period:    DefaultPeriod,
		Key:       key,
	}
}

// WithKey sets the secret key
func (s *Secret) WithKey(key []byte) *Secret { s.Key = key; return s }

// WithDigits sets the secret digits
func (s *Secret) WithDigits(digits uint) *Secret { s.Digits = digits; return s }

// WithAlgorithm sets the secret algorithm
func (s *Secret) WithAlgorithm(algo string) *Secret { s.Algorithm = algo; return s }

// WithPeriod sets the secret period
func (s *Secret) WithPeriod(period time.Duration) *Secret { s.Period = period; return s }

// Key32 returns the key in base32
func (s *Secret) Key32() string { return base32.StdEncoding.EncodeToString(s.Key) }

// String implements fmt.Stringer
func (s *Secret) String() string {
	parts := make([]string, 4)
	if s.Digits != DefaultDigits {
		parts[0] = strconv.Itoa(int(s.Digits))
	}
	if s.Algorithm != DefaultAlgorithm {
		parts[1] = s.Algorithm
	}
	if s.Period != DefaultPeriod {
		parts[2] = s.Period.String()
	}
	parts[3] = s.Key32()
	return strings.Join(parts, ";")
}

func (s *Secret) CounterCode(counter uint) string {
	return CounterCode(s.Key, counter)
}

func (s *Secret) CheckCounterCode(counter uint, code string) bool {
	return s.CounterCode(counter) == code
}

func (s *Secret) CounterCodeNow() string {
	return CounterCodeNow(s.Key)
}

func (s *Secret) CheckCounterCodeNow(code string) bool {
	return s.CounterCodeNow() == code
}

// URL represents a totp url
type URL struct {
	Issuer string
	Label  string
	Secret *Secret
}

// NewURL generates a new url
func NewURL(label, issuer string, secret *Secret) *URL {
	return &URL{
		Issuer: issuer,
		Label:  label,
		Secret: secret,
	}
}

// WithIssuer sets the issuer
func (u *URL) WithIssuer(issuer string) *URL { u.Issuer = issuer; return u }

// WithLabel sets the label
func (u *URL) WithLabel(label string) *URL { u.Label = label; return u }

// WithSecret sets the secret
func (u *URL) WithSecret(secret *Secret) *URL { u.Secret = secret; return u }

// String implements fmt.Stringer
func (k URL) String() string {
	u := &url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   k.Label,
	}
	q := make(url.Values, 5)
	q["secret"] = []string{base32.StdEncoding.EncodeToString(k.Secret.Key)}
	if k.Issuer != "" {
		q["issuer"] = []string{k.Issuer}
	}
	if k.Secret.Algorithm != DefaultAlgorithm {
		q["algorithm"] = []string{string(k.Secret.Algorithm)}
	}
	if k.Secret.Digits != DefaultDigits {
		q["digits"] = []string{strconv.Itoa(int(k.Secret.Digits))}
	}
	if k.Secret.Period != DefaultPeriod {
		q["period"] = []string{strconv.Itoa(int(k.Secret.Period.Seconds()))}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ParseURL parses a totp url
func ParseURL(u string) (*URL, error) {
	// parse and check scheme and host
	totpURL, err := url.Parse(u)
	if err != nil {
		return nil, NewError(InvalidURL, err.Error())
	}
	if strings.ToLower(totpURL.Scheme) != "otpauth" {
		return nil, NewError(InvalidScheme, totpURL.Scheme)
	}
	if strings.ToLower(totpURL.Host) != "totp" {
		return nil, NewError(InvalidOtpType, totpURL.Host)
	}
	r := &URL{
		Label: strings.TrimPrefix(totpURL.Path, "/"),
		Secret: &Secret{
			Algorithm: DefaultAlgorithm,
			Digits:    DefaultDigits,
			Period:    DefaultPeriod,
		},
	}
	if r.Label == "" {
		return nil, NewError(MissingLabel)
	}
	// parse arguments
	for name, vals := range totpURL.Query() {
		switch n := strings.ToLower(name); n {
		case "issuer":
			// issuer
			r.Issuer = vals[0]
		case "algorithm":
			// algorithm
			switch a := strings.ToLower(vals[0]); a {
			case AlgorithmSha1, AlgorithmSha256, AlgorithmSha512:
				r.Secret.Algorithm = a
			default:
				return nil, NewError(InvalidAlgorithm, vals[0])
			}
		case "secret":
			// base32 secret
			var b []byte
			b, err = base32.StdEncoding.DecodeString(vals[0])
			if err != nil {
				return nil, NewError(Base32Decoding, err.Error())
			}
			r.Secret.Key = b
		case "digits":
			// digits
			d, err := strconv.Atoi(vals[0])
			if err != nil {
				return nil, NewError(InvalidDigits, vals[0])
			}
			switch d {
			case 6, 8:
				r.Secret.Digits = uint(d)
			default:
				return nil, NewError(InvalidDigits, vals[0])
			}
		case "period":
			// totp period
			p, err := strconv.Atoi(vals[0])
			if err != nil || p < 1 {
				return nil, NewError(InvalidPeriod, vals[0])
			}
			r.Secret.Period = time.Duration(p) * time.Second
		default:
			return nil, NewError(UnknownArgument, vals[0])
		}
	}
	if len(r.Secret.Key) == 0 {
		return nil, NewError(MissingKey)
	}
	return r, nil
}
