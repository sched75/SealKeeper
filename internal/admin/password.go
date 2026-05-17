package admin

import (
	"errors"
	"fmt"
	"unicode"
)

// ErrPasswordTooWeak is returned by ValidateAdminPassword when an admin-
// supplied password does not meet the ANSSI B3 floor that the console
// applies to every operator account.
//
// PRD: FR-M.4. Operator accounts are an instance-wide credential — they
// must be at least as strong as the strongest tier of generated user
// password.
var ErrPasswordTooWeak = errors.New("admin: password below ANSSI B3 floor")

// AdminPasswordMinLength is the floor we surface to the UI. Combined
// with the character-class check below, a passing password reaches
// ~100 bits of entropy from a 70+ character alphabet — comfortably
// over the ANSSI B3 threshold for typed credentials.
const AdminPasswordMinLength = 16

// AdminPasswordMinClasses is how many of the four character classes
// (lower, upper, digit, symbol) a password must mix. Three is enough
// to defeat naive line-noise like "aaaa...aaaa" of legal length while
// still letting the operator pick a memorable passphrase.
const AdminPasswordMinClasses = 3

// ValidateAdminPassword returns nil when the candidate clears the B3
// policy or a descriptive ErrPasswordTooWeak wrap otherwise. The HTTP
// layer renders the error message directly to the operator.
func ValidateAdminPassword(s string) error {
	if len(s) < AdminPasswordMinLength {
		return fmt.Errorf("%w: minimum %d characters", ErrPasswordTooWeak, AdminPasswordMinLength)
	}
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r), unicode.IsSpace(r):
			hasSymbol = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	if classes < AdminPasswordMinClasses {
		return fmt.Errorf("%w: mix at least %d of lower-case, upper-case, digits and symbols",
			ErrPasswordTooWeak, AdminPasswordMinClasses)
	}
	return nil
}
