package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"log"
	"math/big"
	"time"
)

type Transaction struct {
	ID        []byte
	Timestamp int64
	From      string
	To        string
	Value     int
	Signature []byte
	PubKey    []byte
}

type HashTransaction struct {
	Timestamp int64
	From      string
	To        string
	Value     int
}

const subsidy = 10

func (tx *Transaction) createHashTransaction() HashTransaction {
	return HashTransaction{tx.Timestamp, tx.From, tx.To, tx.Value}
}

// Hash returns the hash of the Transaction
func (tx *Transaction) Hash() []byte {
	var hash [32]byte

	hashTransaction := tx.createHashTransaction()

	hash = sha256.Sum256(hashTransaction.Serialize())

	return hash[:]
}

// Serialize returns a serialized Transaction
func (htx *HashTransaction) Serialize() []byte {
	var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(htx)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

// SignTransaction signs each input of a Transaction
func (tx *Transaction) SignTransaction(privKey ecdsa.PrivateKey) {
	if tx.IsCoinbase() {
		return
	}

	tx.Signature = nil
	// pubKeyHash := Base58Decode(address)
	// pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-4]
	// tx.PubKey = pubKeyHash

	tx.PubKey = GetPublicKey(privKey)

	tx.ID = tx.Hash()

	r, s, err := ecdsa.Sign(rand.Reader, &privKey, tx.ID)
	if err != nil {
		log.Panic(err)
	}
	signature := append(r.Bytes(), s.Bytes()...)
	tx.Signature = signature
}

// Verify verifies signatures of Transaction
func (tx *Transaction) Verify() bool {
	if tx.IsCoinbase() {
		return true
	}

	curve := elliptic.P256()
	tx.Signature = nil
	tx.ID = tx.Hash()
	r := big.Int{}
	s := big.Int{}
	sigLen := len(tx.Signature)
	r.SetBytes(tx.Signature[:(sigLen / 2)])
	s.SetBytes(tx.Signature[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(tx.PubKey)
	x.SetBytes(tx.PubKey[:(keyLen / 2)])
	y.SetBytes(tx.PubKey[(keyLen / 2):])
	rawPubKey := ecdsa.PublicKey{curve, &x, &y}
	if ecdsa.Verify(&rawPubKey, tx.ID, &r, &s) == false {
		return false
	}
	return true
}

func (tx *Transaction) IsCoinbase() bool {
	return false
}

//NewTransaction creates a new transaction
func NewTransaction(from, to string, amount int, bc *Blockchain) *Transaction {
	wallets, err := NewWallets()
	if err != nil {
		log.Panic(err)
	}
	fromWallet := wallets.GetWallet(from)
	avaiable := bc.FindSpendable(fromWallet)
	if avaiable < amount {
		log.Panic("ERROR: Not enough funds")
	}
	tx := Transaction{nil, time.Now().Unix(), from, to, amount, []byte{}, []byte{}}
	tx.ID = tx.Hash()
	tx.SignTransaction(fromWallet.PrivateKey)
	//update from wallet
	fromWallet.BlockAmount(amount)
	toWallet := wallets.GetWallet(to)
	toWallet.BlockAmount(-amount)
	return &tx
}

// NewCoinbaseTX creates a new coinbase transaction
func NewCoinbaseTX(to string) *Transaction {
	tx := Transaction{nil, time.Now().Unix(), "", to, subsidy, []byte{}, []byte{}}
	tx.ID = tx.Hash()

	return &tx
}

func (tx *Transaction) ReFund() {
	wallets, err := NewWallets()
	if err != nil {
		log.Panic(err)
	}
	fromWallet := wallets.GetWallet(tx.From)
	toWallet := wallets.GetWallet(tx.To)
	fromWallet.BlockAmount(-tx.Value)
	toWallet.BlockAmount(tx.Value)
}
