package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"strconv"
	"time"
)

// Block keeps block headers
type Block struct {
	Timestamp     int64
	Data          []byte
	PrevBlockHash []byte
	Hash          []byte
	Nonce         int
}

// SetHash calculates and sets block hash
func (b *Block) SetHash() {
	timestamp := []byte(strconv.FormatInt(b.Timestamp, 10))
	headers := bytes.Join([][]byte{b.PrevBlockHash, b.Data, timestamp}, []byte{})
	hash := sha256.Sum256(headers)

	b.Hash = hash[:]
}

// Serialize serializes the block
func (b *Block) Serialize() []byte {
	var result bytes.Buffer
	encoder := gob.NewEncoder(&result)

	encoder.Encode(b)

	return result.Bytes()
}

// DeserializeBlock deserializes a block
func DeserializeBlock(d []byte) *Block {
	var block Block

	decoder := gob.NewDecoder(bytes.NewReader(d))
	decoder.Decode(&block)

	return &block
}

// NewBlock creates and returns Block
func NewBlock(data string, prevBlockHash []byte) *Block {
	block := &Block{time.Now().Unix(), []byte(data), prevBlockHash, []byte{}, 0}
	pow := NewProofOfWork(block)
	nonce, hash := pow.Run()
	block.Hash = hash
	block.Nonce = nonce
	return block
}

// NewGenesisBlock creates and returns genesis Block
func NewGenesisBlock() *Block {
	return NewBlock("Genesis Block", []byte{})
}
