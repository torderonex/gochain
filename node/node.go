package main

import (
	"blockchain/blockchain"
	"blockchain/network"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
)

var Addresses []string
var User *blockchain.User
var Chain *blockchain.Blockchain
var Block *blockchain.Block
var Filename string
var Mutex sync.Mutex
var IsMining bool
var BreakMining = make(chan bool)

const (
	ADD_BLOCK = iota + 1
	ADD_TX
	GET_BLOCK
	GET_LHASH
	GET_BLNCE
)

func init() {
	if len(os.Args) < 2 {
		panic("failed 1")
	}
	var (
		serveStr     = ""
		addrStr      = ""
		userNewStr   = ""
		userLoadStr  = ""
		chainNewStr  = ""
		chainLoadStr = ""
	)
	var (
		serveExist     = false
		addrExist      = false
		userNewExist   = false
		userLoadExist  = false
		chainNewExist  = false
		chainLoadExist = false
	)

	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
		case strings.HasPrefix(arg, "-serve:"):
			serveStr = strings.Replace(arg, "-serve:", "", 1)
			serveExist = true
		case strings.HasPrefix(arg, "-newchain:"):
			chainNewStr = strings.Replace(arg, "-newchain:", "", 1)
			chainNewExist = true
		case strings.HasPrefix(arg, "-loadchain:"):
			chainLoadStr = strings.Replace(arg, "-loadchain:", "", 1)
			chainLoadExist = true
		case strings.HasPrefix(arg, "-loadaddr:"):
			addrStr = strings.Replace(arg, "-loadaddr:", "", 1)
			addrExist = true
		case strings.HasPrefix(arg, "-newuser:"):
			userNewStr = strings.Replace(arg, "-newuser:", "", 1)
			userNewExist = true
		case strings.HasPrefix(arg, "-loaduser:"):
			userLoadStr = strings.Replace(arg, "-newuser:", "", 1)
			userLoadExist = true
		}
		if !(userNewExist || userLoadExist || addrExist) || !serveExist ||
			!(chainNewExist || chainLoadExist) {
			panic("failed 2")
		}
		var addresses []string
		err := json.Unmarshal(readFile(addrStr), &addresses)
		if err != nil {
			panic("failed 3")
		}
		var mapaddr = make(map[string]bool)
		for _, addr := range addresses {
			if addr == Serve {
				continue
			}
			if _, ok := mapaddr[addr]; ok {
				continue
			}
			mapaddr[addr] = true
			Addresses = append(Addresses, addr)
		}
		if len(Addresses) == 0 {
			panic("failed 4")
		}
		if userNewExist {
			User = newUser(userNewStr)
		} else if userLoadExist {
			User = loadUser(userLoadStr)
		} else if User == nil {
			panic("failed 5")
		}
		if chainNewExist {
			Filename = chainNewStr
			Chain = chainNew(chainNewStr)
		}
		if chainLoadExist {
			Filename = chainNewStr
			Chain = chainLoad(chainNewStr)
		}
		if Chain == nil {
			panic("failed 6")
		}
		Block = blockchain.NewBlock(User.Address(), Chain.LastHash())
	}
}

func main() {
	network.Listen(Serve, handleServer)
	for {
		fmt.Scanln()
	}
}

func handleServer(conn network.Conn, pack *network.Package) {
	network.Handle(ADD_BLOCK, conn, pack, addBlock)
	network.Handle(ADD_TX, conn, pack, addTransaction)
	network.Handle(GET_BLOCK, conn, pack, getBlock)
	network.Handle(GET_LHASH, conn, pack, getLashHash)
	network.Handle(GET_BLNCE, conn, pack, getBalance)
}

func addBlock(pack *network.Package) string {
	splited := strings.Split(pack.Data, SEPARATOR)
	if len(splited) != 3 {
		return "fail"
	}
	block := blockchain.DeserializeBlock(splited[2])
	if !block.IsValid(Chain) {
		currSize := Chain.Size()
		num, err := strconv.Atoi(splited[1])
		if err != nil {
			return "fail"
		}
		if currSize < uint64(num) {
			go compareChains(splited[0], uint64(num))
			return "ok"
		}
		return "fail"
	}
	Mutex.Lock()
	Chain.AddBlock(block)
	Block = blockchain.NewBlock(User.Address(), Chain.LastHash())
	Mutex.Unlock()
	if IsMining {
		BreakMining <- true
		IsMining = false
	}
}

func readFile(filename string) []byte {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil
	}
	return data
}

func newUser(filename string) *blockchain.User {
	user := blockchain.NewUser()
	if user == nil {
		return nil
	}
	err := os.WriteFile(filename, []byte(user.Purse()), 0644)
	if err != nil {
		return nil
	}
	return user
}

func loadUser(filename string) *blockchain.User {
	priv := readFile(filename)
	if priv == nil {
		return nil
	}
	return blockchain.LoadUser(filename)
}

func chainNew(filename string) *blockchain.Blockchain {
	err := blockchain.NewChain(filename, User.Address())
	if err != nil {
		return nil
	}
	return blockchain.LoadChain(filename)
}

func chainLoad(filename string) *blockchain.Blockchain {
	chain := blockchain.LoadChain(filename)
	return chain
}
