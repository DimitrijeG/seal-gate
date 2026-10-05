package cryptography

// gfMul multiplies in GF(2^8) modulo x^8+x^4+x^3+x+1, without branching on its inputs.
func gfMul(a, b byte) byte {
	var p byte
	for range 8 {
		p ^= a & -(b & 1)

		hi := a >> 7 // read the top bit as 0 or 1, before the shift drops it
		a <<= 1
		a ^= 0x1b & -hi

		b >>= 1
	}
	return p
}

// gfInv returns a^254 = a^2·a^4·…·a^128, a's inverse since a^255 = 1; gfInv(0) is 0.
func gfInv(a byte) byte {
	sq := a
	p := byte(1)
	for range 7 {
		sq = gfMul(sq, sq)
		p = gfMul(p, sq)
	}
	return p
}
