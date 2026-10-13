package identity

// Entity is an identity with its own policies; its ID is generated and never reused, and Groups holds group IDs.
type Entity struct {
	ID       string
	Policies []string
	Groups   []string
}
