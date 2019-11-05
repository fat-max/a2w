package a2w

import "testing"

func TestVerify(t *testing.T) {
	plain := "foobar"

	pwd, err := Hash(plain)

	if err != nil {
		t.Fatal(err)
	}

	match, err := Verify(plain, pwd)
	if err != nil {
		t.Fatal(err)
	}

	if !match {
		t.Fatal("expected match")
	}

	match, err = Verify("barfoo", pwd)
	if err != nil {
		t.Fatal(err)
	}

	if match {
		t.Fatal("expected no match")
	}
}