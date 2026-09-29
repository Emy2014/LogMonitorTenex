package auth

import "testing"

func TestHashVerifyRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Fatalf("correct password should verify: ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrong password", hash)
	if err != nil {
		t.Fatalf("a wrong password is not an error: %v", err)
	}
	if ok {
		t.Fatal("wrong password must not verify")
	}
}

// The salt is generated per call, so the same password never produces the same
// stored hash. Equal hashes would let anyone with the table read off which
// accounts share a password.
func TestHashIsSalted(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("two hashes of the same password must differ")
	}
}

func TestMalformedHashIsRejected(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash", "$argon2i$v=19$m=65536,t=3,p=4$AAAA$AAAA",
		"$argon2id$v=19$m=65536,t=3,p=4$!!!$AAAA",
		"$argon2id$v=1$m=65536,t=3,p=4$AAAA$AAAA",
	} {
		if ok, err := VerifyPassword("x", bad); ok || err == nil {
			t.Errorf("%q should be rejected: ok=%v err=%v", bad, ok, err)
		}
	}
}
