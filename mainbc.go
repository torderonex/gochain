package main

import (
	"blockchain/blockchain"
	"fmt"
	"log"
)

const DB_NAME = "blockchain.db"

func main() {
	miner := blockchain.NewUser()
	blockchain.NewChain(DB_NAME, miner.Address())
	chain := blockchain.LoadChain(DB_NAME)
	for i := 0; i < 3; i++ {
		block := blockchain.NewBlock(miner.Address(), chain.LastHash())
		block.AddTransaction(chain, blockchain.NewTransaciton(miner, "aaa", 3, chain.LastHash()))
		block.AddTransaction(chain, blockchain.NewTransaciton(miner, "bbbb", 2, chain.LastHash()))
		block.Accept(chain, miner, make(chan bool))
		chain.AddBlock(block)
	}
	var sblock string
	rows, err := chain.DB.Query("SELECT Block FROM Blockchain")
	if err != nil {
		log.Fatal(err)
	}
	for rows.Next() {
		rows.Scan(&sblock)
		fmt.Println(sblock)
	}
}
