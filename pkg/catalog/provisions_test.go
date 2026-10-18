package catalog_test

import (
	"strings"
)

var contentStopWords = map[string]bool{
	"the": true, "and": true, "for": true, "of": true, "a": true, "an": true,
	"with": true, "on": true, "in": true, "to": true, "or": true, "its": true,
	"that": true, "are": true, "by": true,
}

// distinctive returns the content words of s, lowercased. Comparing these sets is
// how a control's name is checked against the title of the article it cites.
func distinctive(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return r < 'a' || r > 'z'
	}) {
		if len(w) > 3 && !contentStopWords[w] {
			out[w] = true
		}
	}
	return out
}
