package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const walletFile = "wallet.dat"
const addressChecksumLen = 4

type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
	balance    int
	blocked    int
}

// NewWallet creates and returns a Wallet
func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public, 0, 0}

	return &wallet
}

func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	public := GetPublicKey(*private)

	return *private, public
}

//GetPublicKey return publicKey from private key
func GetPublicKey(privateKey ecdsa.PrivateKey) []byte {
	public := append(privateKey.PublicKey.X.Bytes(), privateKey.PublicKey.Y.Bytes()...)
	return public
}

// GetAddress returns wallet address
func (w *Wallet) GetAddress() []byte {
	publicHash := HashPubKey(w.PublicKey)
	versionPayload := append([]byte{version}, publicHash...)
	checksum := checksum(versionPayload)

	fullPayload := append(versionPayload, checksum...)
	address := Base58Encode(fullPayload)

	return address
}

// HashPubKey hashes public key
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160

}

func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

// ValidateAddress check if address if valid
func ValidateAddress(address string) bool {
	pubKeyHash := Base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

//getSpendable get amount avaiable
func (w *Wallet) getSpendable() int {
	return w.balance + w.blocked
}

//BlockAmount block amount
func (w *Wallet) BlockAmount(amount int) bool {
	w.blocked -= amount
	return true
}

//Send send fund
func (w *Wallet) Send(to string, amount int, bc *Blockchain) {
	avaiable := w.getSpendable()
	if avaiable < amount {
		log.Panic("ERROR: Not enough funds")
	}
	from := fmt.Sprintf("%s", w.GetAddress())
	NewTransaction(from, to, amount, bc)
}

// func GetpubKeyHash(privKey ecdsa.PrivateKey) []byte {
// 	address:=
// 	pubKeyHash := Base58Decode(address)
// 	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
// }
