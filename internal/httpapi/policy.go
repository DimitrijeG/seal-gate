package httpapi

import (
	"net/http"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
)

// policyBodyLimit is the only cap on how many rules a policy holds; authorization bounds names and patterns.
const policyBodyLimit = 64 << 10

type policyRequest struct {
	Rules []policyRule `json:"rules"`
}

type policyRule struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

func (h *Handlers) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	var req policyRequest
	if err := decodeJSON(w, r, &req, policyBodyLimit); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	if err := h.Policy.Put(r.Context(), principalFrom(r), req.policy(name)); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

type policyResponse struct {
	Rules []policyRule `json:"rules"`
}

func (h *Handlers) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	policy, err := h.Policy.Get(r.Context(), principalFrom(r), name)
	if err != nil {
		writeError(w, h.Logger, err)
		return
	}

	writeJSON(w, http.StatusOK, newPolicyResponse(policy))
}

func (h *Handlers) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if err := h.Policy.Delete(r.Context(), principalFrom(r), name); err != nil {
		writeError(w, h.Logger, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// policy takes name from the URL, never the body, so a body cannot rename what it writes.
func (req policyRequest) policy(name string) authorization.Policy {
	rules := make([]authorization.Rule, len(req.Rules))
	for i, rule := range req.Rules {
		rules[i] = rule.rule()
	}

	return authorization.Policy{
		Name:  name,
		Rules: rules,
	}
}

func (p policyRule) rule() authorization.Rule {
	capabilities := make([]authorization.Capability, len(p.Capabilities))
	for i, capability := range p.Capabilities {
		capabilities[i] = authorization.Capability(capability)
	}

	return authorization.Rule{
		Path:         p.Path,
		Capabilities: capabilities,
	}
}

// newPolicyResponse leaves out the name: the URL already holds it.
func newPolicyResponse(policy authorization.Policy) policyResponse {
	// make, not a nil slice, so no rules encodes as [] rather than null.
	rules := make([]policyRule, len(policy.Rules))
	for i, rule := range policy.Rules {
		rules[i] = newPolicyRule(rule)
	}

	return policyResponse{Rules: rules}
}

func newPolicyRule(rule authorization.Rule) policyRule {
	capabilities := make([]string, len(rule.Capabilities))
	for i, capability := range rule.Capabilities {
		capabilities[i] = string(capability)
	}

	return policyRule{
		Path:         rule.Path,
		Capabilities: capabilities,
	}
}
