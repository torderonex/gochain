package main

import (
	network "blockchain/network"
	"fmt"
	"strings"
	"time"
)

const (
	TO_UPPER = iota + 1
	TO_LOWER
)
const address = ":8080"

func main() {
	go network.Listen(address, HandleServer)
	time.Sleep(500 * time.Millisecond)
	res := network.SendPackage(address, &network.Package{
		Option: TO_UPPER,
		Data:   "hello world",
	})
	fmt.Println(res)
	res = network.SendPackage(address, &network.Package{
		Option: TO_LOWER,
		Data:   res.Data,
	})
	fmt.Println(res)
}

func HandleServer(conn network.Conn, p *network.Package) {
	network.Handle(TO_UPPER, conn, p, toUpper)
	network.Handle(TO_LOWER, conn, p, toLower)
}

func toUpper(p *network.Package) string {
	return strings.ToUpper(p.Data)
}

func toLower(p *network.Package) string {
	return strings.ToLower(p.Data)
}
