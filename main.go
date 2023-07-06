package main

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/libsv/go-bk/bec"
	"github.com/libsv/go-bk/wif"
	"github.com/pquerna/otp/totp"
)

func main() {
	now := time.Now()
	randomHash := sha256.Sum256([]byte("alice@wallet.com connection request to bob@wallet.com at " + now.String()))

	fmt.Println("Alice generates a random hash and shares it with bob along with her corresponding publicKey")
	fmt.Println("randomHash: ", hex.EncodeToString(randomHash[:]))

	// here's what alice knows
	aliceWif := "L31jqxoa4e8hU2zXDNZVgzuNJfYqgchcxdkDfzc2TL1sAKTy2tSa"
	alice, _ := wif.DecodeWIF(aliceWif)
	a := alice.PrivKey.ToECDSA()

	// see can calculate
	Ax, Ay := bec.S256().ScalarMult(a.X, a.Y, randomHash[:])
	// she shares A (point coordinates)
	Apub := bec.PublicKey{
		X:     Ax,
		Y:     Ay,
		Curve: bec.S256(),
	}
	fmt.Println("alice public key: ", hex.EncodeToString(Apub.SerialiseCompressed()), "\n")

	// here's what bob knows
	bobWif := "KzCktW7nsKWehHVTgwsaYgpy4RHq9YcGUtW2ezDMwtgjWjpjJAYy"
	bob, _ := wif.DecodeWIF(bobWif)
	b := bob.PrivKey.ToECDSA()

	// he can calculate
	Bx, By := bec.S256().ScalarMult(b.X, b.Y, randomHash[:])
	// he shares B point coordinates
	Bpub := bec.PublicKey{
		X:     Bx,
		Y:     By,
		Curve: bec.S256(),
	}
	fmt.Println("Bob is able to calculate his corresponding public key and shares that.")
	fmt.Println("bob public key: ", hex.EncodeToString(Bpub.SerialiseCompressed()), "\n")

	// alice can now calculate
	aSx, aSy := bec.S256().ScalarMult(Bx, By, a.D.Bytes())
	aliceSecret := bec.PublicKey{
		X:     aSx,
		Y:     aSy,
		Curve: bec.S256(),
	}

	// bob can now calculate
	bSx, bSy := bec.S256().ScalarMult(Ax, Ay, b.D.Bytes())
	bobSecret := bec.PublicKey{
		X:     bSx,
		Y:     bSy,
		Curve: bec.S256(),
	}

	// they should be the same
	fmt.Println("They each calculate a shared secret using their private key and the counterpart's derived public key.")
	fmt.Println("alice secret: ", hex.EncodeToString(aliceSecret.X.Bytes()))
	fmt.Println("bob secret: ", hex.EncodeToString(bobSecret.X.Bytes()), "\n")

	sharedSecret := base32.StdEncoding.EncodeToString(aliceSecret.X.Bytes())

	fmt.Println("Alice and Bob can now use the shared secret to generate a time based set of one time passwords (TOTP) to authenticate each other.")
	for x := 0; x < 10; x++ {
		now := time.Now()
		aliceOTP, _ := totp.GenerateCode(sharedSecret, now)
		bobOTP, _ := totp.GenerateCode(sharedSecret, now)
		fmt.Printf("aliceOTP: %s, bobOTP: %s\n", aliceOTP, bobOTP)
		time.Sleep(30 * time.Second)
	}
}
