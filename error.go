package totp

import "fmt"

// Error represents a TOTP error
type Error struct {
	Err  int
	args []interface{}
}

// NewError returns a new TOTP error
func NewError(err int, args ...interface{}) error {
	return &Error{
		Err:  err,
		args: args,
	}
}

// Error implements error
func (te Error) Error() string {
	var a = make([]interface{}, 0, 8)
	if len(te.args) > 0 {
		a = append(a, te.args...)
	}
	return fmt.Sprintf("can't parse TOTP URL: "+totpErrors[te.Err], a...)
}

var totpErrors = map[int]string{
	InvalidURL:       `can't parse URL: %s`,
	InvalidScheme:    `invalid scheme: "%s"`,
	InvalidOtpType:   `unexpected OTP auth type: "%s"`,
	InvalidAlgorithm: `invalid algorithm: "%s"`,
	Base32Decoding:   `can't decode base32 key: "%s"`,
	InvalidDigits:    `invalid number of digits ("%s"). only 6 and 8 allowed`,
	InvalidPeriod:    `invalid period: "%s"`,
	UnknownArgument:  `unknown argument found: "%s"`,
	MissingLabel:     "label is missing",
	MissingKey:       "key is missing",
	CantReadRandom:   `can't read random bytes: %s`,
	NotEnoughRandom:  "couldn't read enough random bytes",
}

// Error codes.
const (
	InvalidURL       = iota // Error parsing the url
	InvalidScheme           // Url scheme != "otpauth".
	InvalidOtpType          // Host in the url must be either "totp"
	InvalidAlgorithm        // Invalid algorithm.
	Base32Decoding          // Base32 decoding error.
	InvalidDigits           // Invalid number of digits.
	InvalidPeriod           // Can't parse period parameter.
	UnknownArgument         // Unknown argument found
	MissingLabel            // Missing (or empty) label.
	MissingKey              // key parameter is missing.
	CantReadRandom          // Something went wrong while reading random bytes.
	NotEnoughRandom         // Didn't read enough random bytes.
)
