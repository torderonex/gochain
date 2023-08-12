package main

import (
	"blockchain/blockchain"
	"blockchain/network"
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var Addresses []string
var User *blockchain.User

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
		addrStr     = ""
		userNewStr  = ""
		userLoadStr = ""
	)
	var (
		addrExist     = false
		userNewExist  = false
		userLoadExist = false
	)
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		switch {
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
		if !(userNewExist || userLoadExist || addrExist) {
			panic("failed 2")
		}
		err := json.Unmarshal(readFile(addrStr), &Addresses)
		if err != nil {
			panic("failed 3")
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

	}
}

func main() {
	clientHandle()
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

func clientHandle() {
	var (
		message string
		splited []string
	)
	for {
		message = inputString("> ")
		splited = strings.Split(message, " ")
		switch splited[0] {
		case "/exit":
			os.Exit(0)
		case "/user":
			if len(splited) < 2 {
				fmt.Println("wrong /user command syntax")
				continue
			}
			switch splited[1] {
			case "address":
				userAddress()
			case "purse":
				userPurse()
			case "balance":
				userBalance()
			}
		case "/chain":
			if len(splited) < 2 {
				fmt.Println("wrong /chain command syntax")
				continue
			}
			switch splited[1] {
			case "print":
				chainPrint()
			case "tx":
				chainTX(splited[1:])
			case "balance":
				chainBalance(splited[1:])
			}
		default:
			fmt.Printf("undefined command\n")

		}
	}
}

func inputString(begin string) string {
	fmt.Print(begin)
	msg, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.Replace(msg, "\n", "", 1)
}

func userAddress() {
	fmt.Printf("Address: %s \n", User.Address())
}

func userPurse() {
	fmt.Printf("Purse: %s \n", User.Purse())
}

func userBalance() {
	printBalance(User.Address())
}

func chainPrint() {
	for i := 0; ; i++ {
		res := network.SendPackage(Addresses[0], &network.Package{
			Option: GET_BLOCK,
			Data:   fmt.Sprintf("%d", i),
		})
		if res == nil || res.Data == "" {
			break
		}
		fmt.Printf("[%d]=> %s\n", i+1, res.Data)
	}
	fmt.Println()
}

func chainTX(splited []string) {
	if len(splited) != 3 {
		fmt.Println("len(splited != 3)")
		return
	}
	num, err := strconv.Atoi(splited[2])
	if err != nil {
		fmt.Println("address parsing error")
		return
	}
	for _, addr := range Addresses {
		res := network.SendPackage(addr, &network.Package{
			Option: GET_LHASH,
		})
		if res == nil {
			continue
		}
		tx := blockchain.NewTransaciton(User, splited[1], uint64(num), blockchain.Base64Decode(res.Data))
		if tx == nil {
			fmt.Println("transaction is invalid")
			return
		}
		res = network.SendPackage(addr, &network.Package{
			Option: ADD_TX,
			Data:   blockchain.SerializateTX(tx),
		})
		if res == nil {
			continue
		}
		if res.Data == "ok" {
			fmt.Printf("ok: (%s)\n", addr)
		} else {
			fmt.Printf("fail: (%s)\n", addr)
		}
		fmt.Println()
	}
}

func chainBalance(splited []string) {
	if len(splited) != 2 {
		fmt.Println("chain balance command wrong syntax")
	}
	printBalance(splited[1])
}

func printBalance(address string) {
	for _, addr := range Addresses {
		res := network.SendPackage(addr, &network.Package{
			Option: GET_BLNCE,
			Data:   address,
		})
		if res == nil {
			continue
		}
		fmt.Printf("Balance (%s) : %s coins", address, res.Data)
	}
}
