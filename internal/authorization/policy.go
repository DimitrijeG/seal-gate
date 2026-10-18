package authorization

// Capability is an action a rule grants on matching resources; deny refuses it whatever else grants it.
type Capability string

const (
	CapabilityCreate Capability = "create"
	CapabilityRead   Capability = "read"
	CapabilityUpdate Capability = "update"
	CapabilityDelete Capability = "delete"
	CapabilityList   Capability = "list"
	CapabilityRotate Capability = "rotate"
	CapabilityDeny   Capability = "deny"
)

func (c Capability) valid() bool {
	switch c {
	case CapabilityCreate, CapabilityRead, CapabilityUpdate, CapabilityDelete,
		CapabilityList, CapabilityRotate, CapabilityDeny:
		return true
	}
	return false
}

// Rule grants its capabilities on every resource its Path matches.
type Rule struct {
	// Path is a resource path, or a prefix ending in '*' that matches everything under it.
	Path         string
	Capabilities []Capability
}

// Policy is a named set of rules; one with no rules grants nothing.
type Policy struct {
	Name  string
	Rules []Rule
}
