package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

const DIFFICULTY = 3

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block *Block
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	return &ProofOfWork{b}
}

func (pow *ProofOfWork) prepareData(nonce int) []byte {
	data := bytes.Join(
		[][]byte{
			pow.block.PrevBlockHash,
			pow.block.HashTransactions(),
			[]byte(strconv.Itoa(nonce)),
		},
		[]byte{},
	)

	return data
}

// Run performs a proof-of-work
func (pow *ProofOfWork) Run() (int, []byte) {
	nonce := 0
	var hash [32]byte

	for true {
		data := pow.prepareData(nonce)
		hash = sha256.Sum256(data)
		if strings.HasPrefix(hex.EncodeToString(hash[:]), strings.Repeat("0", DIFFICULTY)) {
			break
		}
		nonce++
	}
	return nonce, hash[:]
}

// Validate validates block's PoW
func (pow *ProofOfWork) Validate() bool {
	data := pow.prepareData(pow.block.Nonce)
	hash := sha256.Sum256(data)
	return strings.HasPrefix(hex.EncodeToString(hash[:]), strings.Repeat("0", DIFFICULTY))
}
