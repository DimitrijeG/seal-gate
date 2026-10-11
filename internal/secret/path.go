package secret

import "strings"

const maxPathLength = 256

// validPrefix reports whether prefix is empty, or a valid path followed by '/'.
func validPrefix(prefix string) bool {
	if prefix == "" {
		return true
	}
	path, ok := strings.CutSuffix(prefix, "/")
	return ok && validPath(path)
}

// validPath reports whether path is '/'-joined segments of [A-Za-z0-9._-],
// none empty, "." or "..", at most 256 bytes.
func validPath(path string) bool {
	if len(path) > maxPathLength {
		return false
	}

	for segment := range strings.SplitSeq(path, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}

		for i := 0; i < len(segment); i++ {
			if !validByte(segment[i]) {
				return false
			}
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
