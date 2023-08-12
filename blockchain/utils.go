package blockchain

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	mrand "math/rand"
)

const (
	DEBUG = true
)

func hashSum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func generateRandBytes(max int) []byte {
	slice := make([]byte, max)
	_, err := rand.Read(slice)
	if err != nil {
		return nil
	}
	return slice
}

func generatePrivate(bits uint) *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, int(bits))
	if err != nil {
		return nil
	}
	return priv
}
func stringPrivate(private *rsa.PrivateKey) string {
	return Base64Encode(x509.MarshalPKCS1PrivateKey(private))
}

func StringPublic(public *rsa.PublicKey) string {
	return Base64Encode(x509.MarshalPKCS1PublicKey(public))
}

func parsePrivate(privateData string) *rsa.PrivateKey {
	priv, err := x509.ParsePKCS1PrivateKey(Base64Decode(privateData))
	if err != nil {
		return nil
	}
	return priv
}

func uint64ToBytes(value uint64) []byte {
	var data = new(bytes.Buffer)
	err := binary.Write(data, binary.BigEndian, value)
	if err != nil {
		return nil
	}
	return data.Bytes()
}

func sign(private *rsa.PrivateKey, hash []byte) []byte {
	signData, err := rsa.SignPSS(rand.Reader, private, crypto.SHA256, hash, nil)
	if err != nil {
		return nil
	}
	return signData
}

func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func Base64Decode(data string) []byte {
	result, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	return result
}

func SerializateTX(tx *Transaction) string {
	jsonData, err := json.MarshalIndent(tx, " ", " ")
	if err != nil {
		return ""
	}
	return string(jsonData)
}

func DeserializeTX(data string) *Transaction {
	var p Transaction
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil
	}
	return &p
}

func SerializeBlock(block *Block) string {
	jsonData, err := json.MarshalIndent(block, " ", " ")
	if err != nil {
		return ""
	}
	return string(jsonData)
}

func DeserializeBlock(data string) *Block {
	var p Block
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		return nil
	}
	return &p
}
func proofOfWork(blockHash []byte, difficulty uint8, ch chan bool) uint64 {
	var (
		Target  = big.NewInt(1)
		intHash = big.NewInt(1)
		nonce   = uint64(mrand.Intn(math.MaxUint32))
		hash    []byte
	)
	Target.Lsh(Target, 256-uint(difficulty))
	for nonce < math.MaxUint64 {
		select {
		case <-ch:
			if DEBUG {
				fmt.Println()
			}
			return nonce
		default:
			hash = hashSum(bytes.Join(
				[][]byte{
					blockHash,
					uint64ToBytes(nonce),
				},
				[]byte{},
			))
			if DEBUG {
				fmt.Printf("\rMining: %s", Base64Encode(hash))
			}
			intHash.SetBytes(hash)
			if intHash.Cmp(Target) == -1 {
				if DEBUG {
					fmt.Println()
				}
				return nonce
			}
			nonce++
		}
	}
	return nonce
}

func verify(public *rsa.PublicKey, data, signature []byte) error {
	return rsa.VerifyPSS(public, crypto.SHA256, data, signature, nil)
}

func parsePulbic(publicData string) *rsa.PublicKey {
	pub, err := x509.ParsePKCS1PublicKey(Base64Decode(publicData))
	if err != nil {
		return nil
	}
	return pub
}
