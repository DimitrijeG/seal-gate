package app

import (
	"time"
)

type systemClock struct{}

// Now is UTC so persisted timestamps do not depend on the host's time zone.
func (systemClock) Now() time.Time {
	return time.Now().UTC()
}
