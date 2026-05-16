// Package libraries owns uploaded dictionaries and corpora.
//
// PRD references: module A §5.2 (dictionary format) and §5.3 (corpus
// format), plus module C §3.6 (FR-C.47..56) for the admin surface.
//
// This file holds the line-level validators. validator.go is dependency-free
// (no DB, no filesystem) so it can be unit-tested cheaply.
package libraries

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind enumerates the supported library types.
type Kind string

const (
	KindDictionary Kind = "dictionary"
	KindCorpus     Kind = "corpus"
)

// PRD constraints (module A §5.2 / §5.3).
const (
	dictMinWordLen = 4
	dictMaxWordLen = 12
	corpusMinWords = 3
	corpusMaxWords = 25

	// recommendedMinEntries is the floor the PRD asks for (≥ 5000). We do
	// NOT reject below it — uploads of small lists are useful in tests and
	// dev environments. A soft warning is surfaced instead.
	recommendedMinEntries = 5000
)

// LineError is a typed error tied to a 1-indexed line number.
type LineError struct {
	Line   int
	Detail string
}

func (e LineError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Detail) }

// Report aggregates the validator's output.
type Report struct {
	Kind        Kind
	Entries     []string // lower-cased + trimmed for dictionaries, verbatim for corpora
	EntryCount  int
	SizeBytes   int64
	FirstErrors []LineError // truncated to 20 to keep the admin error page readable
	Warnings    []string    // soft notes — usually 'fewer than 5000 entries'
}

// Errors returned on hard validation failures (encoding / nothing parseable).
var (
	ErrInvalidEncoding = errors.New("libraries: file is not valid UTF-8 (or contains a BOM)")
	ErrUnknownKind     = errors.New("libraries: unknown kind")
	ErrEmptyFile       = errors.New("libraries: no usable entries found")
)

// Validate dispatches on Kind.
func Validate(kind Kind, src io.Reader) (Report, error) {
	switch kind {
	case KindDictionary:
		return ValidateDictionary(src)
	case KindCorpus:
		return ValidateCorpus(src)
	default:
		return Report{}, fmt.Errorf("%w: %q", ErrUnknownKind, kind)
	}
}

// ValidateDictionary parses a Diceware-style word list.
//
// Rules per PRD module A §5.2:
//   - UTF-8 without BOM
//   - one word per line, comments (`# …`) skipped
//   - 4 ≤ len(word) ≤ 12 (Unicode characters)
//   - letters only (Unicode category L, plus combining marks for accents)
//   - no duplicates
func ValidateDictionary(src io.Reader) (Report, error) {
	rep := Report{Kind: KindDictionary}
	seen := make(map[string]int) // canonical → first line

	err := readLines(src, func(line int, raw string) {
		word := strings.TrimSpace(raw)
		if word == "" || strings.HasPrefix(word, "#") {
			return
		}
		if !isAllLetters(word) {
			rep.recordError(line, fmt.Sprintf("word %q contains non-letter characters", word))
			return
		}
		runes := []rune(word)
		if len(runes) < dictMinWordLen || len(runes) > dictMaxWordLen {
			rep.recordError(line, fmt.Sprintf("word %q has %d runes (want %d..%d)",
				word, len(runes), dictMinWordLen, dictMaxWordLen))
			return
		}
		canonical := strings.ToLower(word)
		if prev, dup := seen[canonical]; dup {
			rep.recordError(line, fmt.Sprintf("word %q duplicates line %d", word, prev))
			return
		}
		seen[canonical] = line
		rep.Entries = append(rep.Entries, canonical)
	})
	if err != nil {
		return rep, err
	}
	return finish(rep)
}

// ValidateCorpus parses a citation bank.
//
// Rules per PRD module A §5.3:
//   - UTF-8 without BOM
//   - one citation per line, comments (`# …`) skipped
//   - 3 ≤ words(citation) ≤ 25
//   - characters are free (the citation can carry digits, punctuation,
//     diacritics, etc.); we only trim, never re-case.
func ValidateCorpus(src io.Reader) (Report, error) {
	rep := Report{Kind: KindCorpus}
	seen := make(map[string]int)

	err := readLines(src, func(line int, raw string) {
		citation := strings.TrimSpace(raw)
		if citation == "" || strings.HasPrefix(citation, "#") {
			return
		}
		words := strings.FieldsFunc(citation, unicode.IsSpace)
		if len(words) < corpusMinWords || len(words) > corpusMaxWords {
			rep.recordError(line, fmt.Sprintf("citation has %d words (want %d..%d)",
				len(words), corpusMinWords, corpusMaxWords))
			return
		}
		canonical := strings.ToLower(citation)
		if prev, dup := seen[canonical]; dup {
			rep.recordError(line, fmt.Sprintf("citation duplicates line %d", prev))
			return
		}
		seen[canonical] = line
		rep.Entries = append(rep.Entries, citation)
	})
	if err != nil {
		return rep, err
	}
	return finish(rep)
}

// readLines applies fn to every line of `src`. Hard-errors on BOM or
// non-UTF-8 input.
func readLines(src io.Reader, fn func(line int, raw string)) error {
	br := bufio.NewReader(src)
	// Reject UTF-8 BOM. PRD module A §5.2: "UTF-8 sans BOM".
	if first, err := br.Peek(3); err == nil && bytes.Equal(first, []byte{0xEF, 0xBB, 0xBF}) {
		return ErrInvalidEncoding
	}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		if !utf8.ValidString(raw) {
			return ErrInvalidEncoding
		}
		fn(line, raw)
	}
	return sc.Err()
}

// isAllLetters reports whether every rune is a Unicode letter (category L)
// or a combining mark (Mn) used by NFD-decomposed accents.
func isAllLetters(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.Is(unicode.Mn, r) {
			return false
		}
	}
	return true
}

func (r *Report) recordError(line int, detail string) {
	if len(r.FirstErrors) < 20 {
		r.FirstErrors = append(r.FirstErrors, LineError{Line: line, Detail: detail})
	}
}

func finish(rep Report) (Report, error) {
	rep.EntryCount = len(rep.Entries)
	if rep.EntryCount == 0 {
		return rep, ErrEmptyFile
	}
	if rep.EntryCount < recommendedMinEntries {
		rep.Warnings = append(rep.Warnings,
			fmt.Sprintf("%d entries — PRD recommends ≥ %d for production use",
				rep.EntryCount, recommendedMinEntries))
	}
	return rep, nil
}

// HasErrors reports whether the report contains any hard errors.
func (r Report) HasErrors() bool { return len(r.FirstErrors) > 0 }
