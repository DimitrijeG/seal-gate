package system

// Keyring owns key material, leaving Service with only the state machine.
// Methods are unexported so only the state machine decides when keys move.
type Keyring struct {
	repository Repository
	sharing    SecretSharing
	wrapper    KeyWrapper
	random     RandomGenerator
	active     ActiveKeyController
}

func NewKeyring(
	repo Repository,
	sharing SecretSharing,
	wrapper KeyWrapper,
	random RandomGenerator,
	active ActiveKeyController,
) *Keyring {
	return &Keyring{repository: repo, sharing: sharing, wrapper: wrapper, random: random, active: active}
}
