package authorization

import "strings"

const (
	maxNameLength    = 128
	maxPatternLength = 257
)

func validName(name string) bool {
	return len(name) <= maxNameLength && validSegment(name)
}

func validRule(rule Rule) bool {
	if !validPattern(rule.Path) || len(rule.Capabilities) == 0 {
		return false
	}

	for _, capability := range rule.Capabilities {
		if !capability.valid() {
			return false
		}
	}
	return true
}

// validPattern accepts a path, or a prefix ending in '*': a path, a path plus '/', or nothing.
func validPattern(pattern string) bool {
	if len(pattern) > maxPatternLength {
		return false
	}

	prefix, starred := strings.CutSuffix(pattern, "*")
	if !starred {
		return validPath(pattern)
	}
	if prefix == "" {
		return true
	}
	return validPath(strings.TrimSuffix(prefix, "/"))
}

func validPath(path string) bool {
	for segment := range strings.SplitSeq(path, "/") {
		if !validSegment(segment) {
			return false
		}
	}
	return true
}

func validSegment(segment string) bool {
	if segment == "" || segment == "." || segment == ".." {
		return false
	}

	for i := 0; i < len(segment); i++ {
		if !validByte(segment[i]) {
			return false
		}
	}
	return true
}

func validByte(b byte) bool {
	return (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= '0' && b <= '9') ||
		b == '.' || b == '_' || b == '-'
}
