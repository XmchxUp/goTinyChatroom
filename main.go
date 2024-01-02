package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

type Client struct {
	conn     net.Conn
	nickname string
}

type ChatRoom struct {
	clients   map[net.Conn]*Client
	m         sync.RWMutex
	maxClient int
}

var (
	port = flag.Int("p", 9999, "port")
	room = &ChatRoom{
		maxClient: 10,
		clients:   make(map[net.Conn]*Client, 10),
	}
)

func closeClient(client *Client) {
	fmt.Printf("%s quit\n", client.nickname)
	client.conn.Close()
	delete(room.clients, client.conn)
}

func handleClient(client *Client) {
	client.conn.Write([]byte(fmt.Sprintf("Welcome to chat room.\nuse /c change nickname. Your default nickname is %s.\n", client.nickname)))

	for {
		msg, err := bufio.NewReader(client.conn).ReadString('\n')
		if err == io.EOF {
			closeClient(client)
			return
		}
		if err != nil {
			fmt.Printf("%s handle error %v\n", client.nickname, err)
			continue
		}
		// remove \r\n
		msg = strings.TrimSpace(msg)
		if len(msg) == 0 {
			continue
		}

		if len(msg) > 0 && msg[0] == '/' {
			parts := strings.SplitN(msg, " ", 2)
			cmd := parts[0]
			if cmd == "/c" && len(parts) == 2 {
				client.nickname = parts[1]
			}
			continue
		}

		if strings.ToLower(msg) == "quit" {
			closeClient(client)
			return
		}

		wrappedMsg := fmt.Sprintf("%s: %s\n", client.nickname, msg)
		fmt.Print(wrappedMsg)
		room.m.RLock()
		for k, v := range room.clients {
			if k == client.conn {
				continue
			}
			v.conn.Write([]byte(wrappedMsg))
		}
		room.m.RUnlock()
	}
}

func main() {
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		fmt.Printf("Err: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Welcome to chat room")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("accept error: %v\n", err)
			continue
		}

		if len(room.clients) >= room.maxClient {
			fmt.Printf("Too many client, reject %s\n", conn.RemoteAddr())
			conn.Close()
			continue
		}

		client := &Client{conn: conn,
			nickname: fmt.Sprintf("client%d", conn.RemoteAddr().(*net.TCPAddr).Port),
		}

		room.m.Lock()
		room.clients[conn] = client
		room.maxClient += 1
		room.m.Unlock()

		go handleClient(client)
		fmt.Printf("new client: %s\n", conn.RemoteAddr())
	}
}
