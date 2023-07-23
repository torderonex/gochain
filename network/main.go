package network

import (
	"encoding/json"
	"log"
	"net"
	"strings"
	"time"
)

type Package struct {
	Option int
	Data   string
}

const (
	ENDBYTES      = "\000\000\001\005\001\000\000"
	WAITTIME      = 5
	MAXMESSAGELEN = 2 << 20
)

type Listener net.Listener
type Conn net.Conn

func Listen(address string, handler func(Conn, *Package)) Listener {
	parts := strings.Split(address, ":")
	if len(parts) != 2 {
		return nil
	}
	listener, err := net.Listen("tcp", "0.0.0.0:"+parts[1])
	if err != nil {
		return nil
	}
	go serve(listener, handler)
	return listener
}

func Handle(opt int, conn Conn, p *Package, handler func(*Package) string) bool {
	if p.Option != opt {
		return false
	}
	_, err := conn.Write([]byte(SerializePackage(&Package{
		Option: opt,
		Data:   handler(p),
	}) + ENDBYTES))
	return err == nil
}

func handleConn(conn net.Conn, handler func(Conn, *Package)) {
	defer conn.Close()
	p := readPackage(conn)
	if p == nil {
		return
	}
	handler(conn, p)
}

func serve(listener Listener, handler func(Conn, *Package)) {
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			break
		}
		go handleConn(conn, handler)
	}
}

func SerializePackage(p *Package) string {
	data, err := json.MarshalIndent(p, " ", " ")
	if err != nil {
		log.Fatal("serialization error: ", err)
	}
	return string(data)
}

func DeserializePackage(data string) *Package {
	var p Package
	if err := json.Unmarshal([]byte(data), &p); err != nil {
		log.Fatal(err)
		return nil
	}
	return &p
}

func SendPackage(address string, p *Package) *Package {
	conn, err := net.Dial("tcp", address)
	if err != nil {
		log.Fatal("connection error ", err)
		return nil
	}
	defer conn.Close()
	_, err = conn.Write([]byte(SerializePackage(p) + ENDBYTES))
	if err != nil {
		log.Fatal(err)
		return nil
	}
	res := new(Package)
	isDelivered := make(chan bool)

	go func() {
		res = readPackage(conn)
		isDelivered <- true
	}()

	select {
	case <-isDelivered:
	case <-time.After(time.Second * WAITTIME):
	}
	return res
}

func readPackage(conn net.Conn) *Package {
	var buffer = make([]byte, 2048)
	var data string
	var sumLen uint64
	for {
		length, err := conn.Read(buffer)
		if err != nil {
			return nil
		}
		sumLen += uint64(length)
		if sumLen > MAXMESSAGELEN {
			return nil
		}
		data += string(buffer[:length])
		if strings.Contains(data, ENDBYTES) {
			data = strings.Split(data, ENDBYTES)[0]
			break
		}
	}
	return DeserializePackage(data)

}
