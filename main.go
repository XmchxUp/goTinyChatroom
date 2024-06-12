package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

type Role int

const (
	AdminRole Role = iota
	UserRole
)

type User struct {
	username string
	nickname string
	password string
	Role
}

type Client struct {
	conn net.Conn
	user *User
	room *ChatRoom
}

type ChatRoom struct {
	id        int
	name      string
	clients   map[net.Conn]*Client
	m         sync.RWMutex
	maxClient int
	owner     User
}

type Server struct {
	users           map[string]*User
	rooms           map[int]*ChatRoom
	clients         map[net.Conn]*Client
	m               sync.RWMutex
	roomMaxCapacity int
}

var (
	port   = flag.Int("p", 9999, "port")
	server = &Server{
		roomMaxCapacity: 3,
		clients:         make(map[net.Conn]*Client),
		users:           make(map[string]*User),
		rooms:           make(map[int]*ChatRoom),
	}
)

func init() {
	registerUser("admin", "gtc", AdminRole)
}

func main() {
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		fmt.Printf("Err: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Start chat room")
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("accept error: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}

func registerUser(username, password string, role Role) error {
	server.m.Lock()
	defer server.m.Unlock()
	if _, exists := server.users[username]; exists {
		return fmt.Errorf("username already exists")
	}
	server.users[username] = &User{username: username, password: hashPassword(password), Role: role}
	return nil
}

func authenticateUser(username, password string) (*User, error) {
	server.m.RLock()
	defer server.m.RUnlock()

	user, exists := server.users[username]
	if !exists {
		return nil, fmt.Errorf("user does not exist")
	}

	if user.password != hashPassword(password) {
		return nil, fmt.Errorf("invalid password")
	}
	return user, nil
}

func hashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return hex.EncodeToString(hash[:])
}

func closeClient(client *Client) {
	// fmt.Printf("%s quit\n", client.nickname)
	client.conn.Close()
	delete(server.clients, client.conn)
}

func getHelp() string {
	return `
command: 
- /register <username> <password> 
- /login <username> <password>
- /change nickname # change your nickname
- /join <room id> # join one room
- /list # show all room info
- /create # create one chat room
- /q # quit
`
}

func handleUserLogin(conn net.Conn, reader *bufio.Reader) *User {
	for {
		command, err := reader.ReadString('\n')

		if err == io.EOF {
			return nil
		}

		if err != nil {
			fmt.Printf("%s handle error %v\n", conn.RemoteAddr(), err)
			continue
		}

		command = strings.TrimSpace(command)
		parts := strings.Split(command, " ")
		if len(parts) < 3 {
			conn.Write([]byte("Not accepted.\n" + getHelp()))
			continue
		}

		switch parts[0] {
		case "/register":
			err := registerUser(parts[1], parts[2], UserRole)
			if err != nil {
				conn.Write([]byte(fmt.Sprintf("Error: %v\n", err)))
			} else {
				conn.Write([]byte("Registration successful. Please login.\n"))
			}
		case "/login":
			user, err := authenticateUser(parts[1], parts[2])
			if err != nil {
				conn.Write([]byte(fmt.Sprintf("Error: %v\n", err)))
			} else {
				fmt.Printf("Login Successful %s\n", user.username)
				conn.Write([]byte("Login successful.\nNow you can join one room.\n"))
				return user
			}
		default:
			conn.Write([]byte("Invalid command.\n"))
		}
	}
}

func handleConnection(conn net.Conn) {
	fmt.Printf("new client: %s\n", conn.RemoteAddr())

	// if len(server.clients) >= server.roomMaxCapacity {
	// 	fmt.Printf("Too many client, reject %s\n", conn.RemoteAddr())
	// 	conn.Close()
	// 	continue
	// }

	// client := &Client{conn: conn,
	// 	nickname: fmt.Sprintf("client%d", conn.RemoteAddr().(*net.TCPAddr).Port),
	// }

	conn.Write([]byte("Welcome to tiny chat server. Please register or login.\n" + getHelp()))

	var user *User
	reader := bufio.NewReader(conn)

	user = handleUserLogin(conn, reader)
	if user == nil {
		return
	}
	fmt.Printf("Login Successful %s\n", user.username)

	for {
		command, err := reader.ReadString('\n')

		if err == io.EOF {
			return
		}

		if err != nil {
			fmt.Printf("%s handle error %v\n", conn.RemoteAddr(), err)
			continue
		}

		command = strings.TrimSpace(command)
		parts := strings.Split(command, " ")
		if len(parts) < 3 {
			conn.Write([]byte("Not accepted.\n" + getHelp()))
			continue
		}
	}

	// msg, err := reader.ReadString('\n')
	// 		if err == io.EOF {
	// 			closeClient(client)
	// 			return
	// 		}
	// 		if err != nil {
	// 			fmt.Printf("%s handle error %v\n", client.nickname, err)
	// 			continue
	// 		}
	// 		// remove \r\n
	// 		msg = strings.TrimSpace(msg)
	// 		if len(msg) == 0 {
	// 			continue
	// 		}

	// 		if len(msg) > 0 && msg[0] == '/' {
	// 			parts := strings.SplitN(msg, " ", 2)
	// 			cmd := parts[0]
	// 			if cmd == "/c" && len(parts) == 2 {
	// 				client.nickname = parts[1]
	// 			}
	// 			continue
	// 		}

	// 		if strings.ToLower(msg) == "quit" {
	// 			closeClient(client)
	// 			return
	// 		}

	// wrappedMsg := fmt.Sprintf("%s: %s\n", client.nickname, msg)
	// fmt.Print(wrappedMsg)
	// server.m.RLock()
	//
	//	for k, v := range server.clients {
	//		if k == client.conn {
	//			continue
	//		}
	//		v.conn.Write([]byte(wrappedMsg))
	//	}
	//
	// server.m.RUnlock()
}
