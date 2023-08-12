package blockchain

import (
	"bytes"
	"crypto/rsa"
	"database/sql"
	"errors"
	"math/big"
	"os"
	"sort"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Blockchain struct {
	DB    *sql.DB
	Index uint64
}

type Block struct {
	CurrHash     []byte
	PrevHash     []byte
	Nonce        uint64
	Diffuclty    uint8
	Miner        string
	Signature    []byte
	TimeStamp    string
	Transactions []Transaction
	Mapping      map[string]uint64
}

type Transaction struct {
	Sender    string
	Receiver  string
	Value     uint64
	ToStorage uint64
	CurrHash  []byte
	Signature []byte
	RandBytes []byte
	PrevBlock []byte
}

type User struct {
	PrivateKey *rsa.PrivateKey
}

const (
	CREATE_TABLE = `
CREATE TABLE BlockChain (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Hash VARCHAR(44) UNIQUE,
    Block TEXT
);
`
)

const (
	KEY_SIZE       = 512
	STORAGE_CHAIN  = "STORAGE-CHAIN"
	STORAGE_VALUE  = 100
	STORAGE_REWARD = 1
	GENESIS_BLOCK  = "GENESIS-BLOCK"
	GENESIS_REWARD = 100
	DIFFICULTY     = 15
	TXS_LIMIT      = 2
	START_PERCENT  = 10
	RAND_BYTES     = 32
)

func NewUser() *User {
	return &User{
		PrivateKey: generatePrivate(KEY_SIZE),
	}
}

func LoadUser(purse string) *User {
	priv := parsePrivate(purse)
	if priv == nil {
		return nil
	}
	return &User{
		PrivateKey: priv,
	}
}

func (user *User) Purse() string {
	return stringPrivate(user.Private())
}

func (chain *Blockchain) LastHash() []byte {
	var hash string
	row := chain.DB.QueryRow("SELECT Hash FROM Blockchain ORDER BY Id DESC")
	row.Scan(&hash)
	return Base64Decode(hash)
}

func (block *Block) isValid(chain *Blockchain) bool {
	switch {
	case block == nil:
		return false
	case block.Diffuclty != DIFFICULTY:
		return false
	case !block.hashIsValid(chain, chain.Size()):
		return false
	case !block.signIsValid():
		return false
	case !block.proofIsValid():
		return false
	case !block.mappingIsValid():
		return false
	case !block.timeIsValid(chain, chain.Size()):
		return false
	case !block.transactionIsValid(chain):
		return false
	}
	return true
}

func (block *Block) hashIsValid(chain *Blockchain, index uint64) bool {
	if !bytes.Equal(block.hash(), block.CurrHash) {
		return false
	}
	var id uint64
	row := chain.DB.QueryRow("SELECT Id FROM Blockchain WHERE Hash=$1", Base64Encode(block.PrevHash))
	row.Scan(&id)
	return id == index
}

func (block *Block) signIsValid() bool {
	return verify(parsePulbic(block.Miner), block.CurrHash, block.Signature) == nil
}

func (block *Block) proofIsValid() bool {
	intHash := big.NewInt(1)
	target := big.NewInt(1)
	hash := hashSum(bytes.Join(
		[][]byte{
			block.CurrHash,
			uint64ToBytes(block.Nonce),
		},
		[]byte{}))
	intHash.SetBytes(hash)
	target.Lsh(target, 256-uint(block.Diffuclty))
	if intHash.Cmp(target) == -1 {
		return true
	}
	return false
}

func (block *Block) mappingIsValid() bool {
	for addr := range block.Mapping {
		if addr == STORAGE_CHAIN {
			continue
		}
		flag := false
		for _, tx := range block.Transactions {
			if tx.Receiver == addr || tx.Sender == addr {
				flag = true
				break
			}
		}
		if !flag {
			return false
		}
	}
	return true
}

func (block *Block) timeIsValid(chain *Blockchain, index uint64) bool {
	btime, err := time.Parse(time.RFC3339, block.TimeStamp)
	if err != nil {
		return false
	}
	diff := time.Now().Sub(btime)
	if diff < 0 {
		return false
	}
	var sblock string
	row := chain.DB.QueryRow("SELECT Block FROM Blockchain WHERE Hash=$1", Base64Encode(block.PrevHash))
	row.Scan(&sblock)
	lblock := DeserializeBlock(sblock)
	if lblock == nil {
		return false
	}
	ltime, err := time.Parse(time.RFC3339, lblock.TimeStamp)
	if err != nil {
		return false
	}
	diff = btime.Sub(ltime)

	return diff > 0
}

func NewChain(filename, receiver string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	f.Close()
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(CREATE_TABLE)
	if err != nil {
		return err
	}
	chain := &Blockchain{
		DB: db,
	}
	genesis := &Block{
		CurrHash:  []byte(GENESIS_BLOCK),
		Mapping:   make(map[string]uint64),
		Miner:     receiver,
		TimeStamp: time.Now().Format(time.RFC3339),
	}
	genesis.Mapping[STORAGE_CHAIN] = STORAGE_VALUE
	genesis.Mapping[receiver] = GENESIS_REWARD
	chain.AddBlock(genesis)
	return nil
}

func LoadChain(filename string) *Blockchain {
	db, err := sql.Open("sqlite3", filename)
	if err != nil {
		return nil
	}
	chain := &Blockchain{
		DB: db,
	}
	chain.Index = chain.Size()
	return chain
}

func NewBlock(miner string, prevHash []byte) *Block {
	return &Block{
		Diffuclty: DIFFICULTY,
		PrevHash:  prevHash,
		Miner:     miner,
		Mapping:   make(map[string]uint64),
	}
}

func NewTransaciton(user *User, receiver string, value uint64, lastHash []byte) *Transaction {
	tx := &Transaction{
		Sender:    user.Address(),
		Receiver:  receiver,
		Value:     value,
		RandBytes: generateRandBytes(RAND_BYTES),
		PrevBlock: lastHash,
	}
	if value > START_PERCENT {
		tx.ToStorage = STORAGE_REWARD
	}
	tx.CurrHash = tx.hash()
	tx.Signature = tx.sign(user.Private())
	return tx
}

func (block *Block) AddTransaction(chain *Blockchain, tx *Transaction) error {
	if tx == nil {
		return errors.New("tx is null")
	}
	if tx.Value == 0 {
		return errors.New("tx value = 0")
	}
	if len(block.Transactions) == TXS_LIMIT && tx.Sender != STORAGE_CHAIN {
		return errors.New("transactions limit")
	}
	var balanceInChain uint64
	balanceTx := tx.Value + tx.ToStorage
	if value, ok := block.Mapping[tx.Sender]; ok {
		balanceInChain = value
	} else {
		balanceInChain = chain.Balance(tx.Sender)
	}
	if tx.Value > START_PERCENT && tx.ToStorage != STORAGE_REWARD {
		return errors.New("storage reward passed")
	}
	if balanceTx > balanceInChain {
		return errors.New("balance in transaction > chain balance")
	}
	block.Mapping[tx.Sender] = balanceInChain - balanceTx
	block.addBalance(chain, tx.Receiver, tx.Value)
	block.addBalance(chain, STORAGE_CHAIN, tx.ToStorage)
	block.Transactions = append(block.Transactions, *tx)
	return nil
}

func (block *Block) Accept(chain *Blockchain, user *User, ch chan bool) error {
	if !block.transactionIsValid(chain) {
		return errors.New("transaction is not valid")
	}
	block.AddTransaction(chain, &Transaction{
		RandBytes: generateRandBytes(RAND_BYTES),
		Sender:    STORAGE_CHAIN,
		Receiver:  user.Address(),
		Value:     STORAGE_REWARD,
	})

	block.TimeStamp = time.Now().Format(time.RFC3339)
	block.CurrHash = block.hash()
	block.Signature = block.sign(user.Private())
	block.Nonce = block.proof(ch)
	return nil
}

func (block *Block) transactionIsValid(chain *Blockchain) bool {
	lentx := len(block.Transactions)
	plusStorage := 0
	for i := 0; i < lentx; i++ {
		if block.Transactions[i].Sender == STORAGE_CHAIN {
			plusStorage = 1
			break
		}
	}
	if lentx == 0 || lentx > TXS_LIMIT+plusStorage {
		return false
	}
	for i := 0; i < lentx; i++ {
		for j := i + 1; j < lentx; j++ {
			if bytes.Equal(block.Transactions[i].RandBytes, block.Transactions[j].RandBytes) {
				return false
			}
			if block.Transactions[i].Sender == STORAGE_CHAIN &&
				block.Transactions[j].Sender == STORAGE_CHAIN {
				return false
			}
		}
	}
	for i := 0; i < lentx; i++ {
		tx := block.Transactions[i]
		if tx.Sender == STORAGE_CHAIN {
			if tx.Receiver != block.Miner || tx.Value != STORAGE_REWARD {
				return false
			} else {
				if !tx.hashIsValid() || !tx.signIsValid() {
					return false
				}
			}
			if !block.balanceIsValid(chain, tx.Sender) || !block.balanceIsValid(chain, tx.Receiver) {
				return false
			}
		}
	}
	return true
}

func (block *Block) hash() []byte {
	var tempHash []byte
	for _, tx := range block.Transactions {
		tempHash = hashSum(bytes.Join(
			[][]byte{
				tempHash,
				tx.CurrHash,
			},
			[]byte{}))
	}
	var list []string
	for hash := range block.Mapping {
		list = append(list, hash)
	}
	sort.Strings(list)
	for _, addr := range list {
		tempHash = hashSum(bytes.Join(
			[][]byte{
				tempHash,
				[]byte(addr),
				uint64ToBytes(block.Mapping[addr]),
			},
			[]byte{}))
	}
	return hashSum(bytes.Join(
		[][]byte{
			tempHash,
			uint64ToBytes(uint64(block.Diffuclty)),
			block.PrevHash,
			[]byte(block.Miner),
			[]byte(block.TimeStamp),
		},
		[]byte{}))
}

func (block *Block) sign(private *rsa.PrivateKey) []byte {
	return sign(private, block.CurrHash)
}

func (block *Block) proof(ch chan bool) uint64 {
	return proofOfWork(block.CurrHash, block.Diffuclty, ch)
}

func (tx *Transaction) hashIsValid() bool {
	return bytes.Equal(tx.hash(), tx.CurrHash)
}

func (tx *Transaction) signIsValid() bool {
	return verify(parsePulbic(tx.Sender), tx.CurrHash, tx.Signature) == nil
}

func (block *Block) balanceIsValid(chain *Blockchain, address string) bool {
	if _, ok := block.Mapping[address]; !ok {
		return false
	}
	lentx := len(block.Transactions)
	balanceInChain := chain.Balance(address)
	balanceSubBlock := uint64(0)
	balanceAddBlock := uint64(0)
	for j := 0; j < lentx; j++ {
		tx := block.Transactions[j]
		if tx.Sender == address {
			balanceSubBlock += tx.Value + tx.ToStorage
		}
		if tx.Receiver == address {
			balanceAddBlock += tx.Value
		}
		if tx.Receiver == address && STORAGE_CHAIN == address {
			balanceAddBlock += tx.ToStorage
		}
	}
	if balanceInChain+balanceAddBlock-balanceSubBlock != block.Mapping[address] {
		return false
	}
	return true
}

func (block *Block) addBalance(chain *Blockchain, receiver string, value uint64) {
	var balance uint64
	if value, ok := block.Mapping[receiver]; ok {
		balance = value
	} else {
		balance = chain.Balance(receiver)
	}
	block.Mapping[receiver] = balance + value
}

func (chain *Blockchain) Balance(address string) uint64 {
	var balance uint64
	var sblock string
	var block *Block
	rows, err := chain.DB.Query("SELECT Block FROM Blockchain WHERE Id <= $1 ORDER BY Id Desc", chain.Index)
	if err != nil {
		return balance
	}
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&sblock)
		block = DeserializeBlock(sblock)
		if value, ok := block.Mapping[address]; ok {
			balance = value
			break
		}
	}
	return balance

}

func (user *User) Address() string {
	return StringPublic(user.Public())
}

func (user *User) Private() *rsa.PrivateKey {
	return user.PrivateKey
}

func (tx *Transaction) hash() []byte {
	return hashSum(bytes.Join([][]byte{
		tx.RandBytes,
		tx.PrevBlock,
		[]byte(tx.Sender),
		[]byte(tx.Receiver),
		uint64ToBytes(tx.ToStorage),
		uint64ToBytes(tx.Value),
	}, []byte{}))
}

func (tx *Transaction) sign(private *rsa.PrivateKey) []byte {
	return sign(private, tx.CurrHash)
}

func (user *User) Public() *rsa.PublicKey {
	return &(user.PrivateKey).PublicKey
}

func (chain *Blockchain) AddBlock(block *Block) {
	chain.Index++
	chain.DB.Exec("INSERT INTO Blockchain (Hash, Block) VALUES ($1, $2)", Base64Encode(block.CurrHash), SerializeBlock(block))
}

func (chain *Blockchain) Size() uint64 {
	var index uint64
	row := chain.DB.QueryRow("SELECT Id FROM Blockchain ORDER BY Id DESC")
	row.Scan(&index)
	return index
}
