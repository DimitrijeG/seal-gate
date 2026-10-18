package authorization

import (
	"context"
	"errors"
)

// Grants is what a principal may do: the root passes every check, anyone else holds Rules.
type Grants struct {
	Root  bool
	Rules []Rule
}

// Rules returns principal's rules as stored, in policy order and unmerged, so a deny is never folded into a grant.
// A missing policy adds none; any other read failure is returned as is, as Authorize does.
func (s *Service) Rules(ctx context.Context, principal Principal) (Grants, error) {
	if principal.root {
		return Grants{Root: true}, nil
	}

	var grants Grants
	for _, name := range principal.policies {
		policy, err := s.get(ctx, name)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return Grants{}, err
		}
		grants.Rules = append(grants.Rules, policy.Rules...)
	}
	return grants, nil
}
