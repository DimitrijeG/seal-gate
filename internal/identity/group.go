package identity

// Group assigns its policies to the entities that name it; its ID is generated and never reused, and it holds no member list.
type Group struct {
	ID       string
	Policies []string
}
