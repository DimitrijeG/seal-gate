package secret

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ActionKind names what a sweep did to a secret.
type ActionKind string

const (
	ActionRotated ActionKind = "rotated"
	ActionExpired ActionKind = "expired"
)

// Action is one change a sweep made: the path and what happened to it, never the value.
type Action struct {
	Path string
	Kind ActionKind
}

// Sweep rotates every generated secret that is due and deletes every expired stored one, reporting each as it is done.
// A failed path does not stop it: failures return joined, except ErrSealed, which ends the sweep at once.
func (s *Service) Sweep(ctx context.Context, report func(Action)) error {
	now := s.clock.Now()
	paths, err := s.repo.List(ctx, "")
	switch {
	case ours(err):
		return err
	case err != nil:
		return fmt.Errorf("secret: %w", err)
	}

	var failures []error
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("secret: %w", err)
		}
		action, acted, err := s.sweepPath(ctx, path, now)
		if errors.Is(err, ErrSealed) {
			return err
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		// After sweepPath has unlocked, so a slow report never blocks writes.
		if acted {
			report(action)
		}
	}
	return errors.Join(failures...)
}

// sweepPath rotates or deletes path if it is due, reporting whether it did; a path gone since List is skipped.
func (s *Service) sweepPath(ctx context.Context, path string, now time.Time) (Action, bool, error) {
	// Held per path, read included, so a put since List is seen; held for the whole scan, it would block every write.
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, err := s.repo.Get(ctx, path)
	switch {
	case errors.Is(err, ErrNotFound):
		return Action{}, false, nil
	case errors.Is(err, ErrSealed):
		return Action{}, false, err
	case ours(err):
		return Action{}, false, fmt.Errorf("%s: %w", path, err)
	case err != nil:
		return Action{}, false, fmt.Errorf("secret: %s: %w", path, err)
	}
	length := len(entry.Value)
	clear(entry.Value)

	switch {
	case entry.due(now):
		value, err := s.storeGenerated(ctx, path, length, entry.TTL)
		switch {
		case errors.Is(err, ErrSealed):
			return Action{}, false, err
		case err != nil:
			// Already prefixed by storeGenerated; only the path is added.
			return Action{}, false, fmt.Errorf("%s: %w", path, err)
		}
		clear(value)
		return Action{Path: path, Kind: ActionRotated}, true, nil
	case entry.expired(now):
		err := s.repo.Delete(ctx, path)
		switch {
		case errors.Is(err, ErrSealed):
			return Action{}, false, err
		case err != nil:
			return Action{}, false, fmt.Errorf("secret: %s: %w", path, err)
		}
		return Action{Path: path, Kind: ActionExpired}, true, nil
	}
	return Action{}, false, nil
}
