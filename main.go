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
	"strconv"
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
	password string
	Role
}

type ChatRoom struct {
	id        int
	name      string
	clients   map[net.Conn]*Client
	m         sync.RWMutex
	maxClient int
	owner     *User
}

type Client struct {
	conn net.Conn
	user *User
	room *ChatRoom
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
	atomicRoomID = 0
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

func closeConnection(conn net.Conn) {
	fmt.Printf("%s connection closed\n", conn.RemoteAddr().String())
	conn.Close()

	server.m.Lock()
	defer server.m.Unlock()

	delete(server.clients, conn)
}

func getHelp() string {
	return `
command: 
- /register <username> <password> 
- /login <username> <password>
- /join <room id> # join one room
- /delete <room id> # delete one room
- /leave # leave room
- /list # show all room info
- /create <room name> # create one chat room
- /send msg
- /quit
- /help
`
}

func listRoom(client *Client) {
	server.m.RLock()
	defer server.m.RUnlock()
	if len(server.rooms) == 0 {
		client.conn.Write([]byte("empty room\n"))
		return
	}

	var sb strings.Builder
	sb.WriteString("Rooms:\n")
	for id, room := range server.rooms {
		sb.WriteString(fmt.Sprintf("%d %s\n", id, room.name))
	}
	client.conn.Write([]byte(sb.String()))
}

func deleteRoom(client *Client, roomID int) {
	if client.user.Role != AdminRole {
		client.conn.Write([]byte("need admin role\n"))
		return
	}

	server.m.Lock()
	defer server.m.Unlock()

	room, exists := server.rooms[roomID]
	if !exists {
		client.conn.Write([]byte("not found room\n"))
		return
	}

	for _, v := range room.clients {
		v.room = nil
	}

	delete(server.rooms, roomID)
	client.conn.Write([]byte(fmt.Sprintf("delete %d room\n", roomID)))
}

func leaveRoom(client *Client) {
	if client.room == nil {
		client.conn.Write([]byte("leave: empty room\n"))
		return
	}

	client.room.m.Lock()
	defer client.room.m.Unlock()
	client.conn.Write([]byte(fmt.Sprintf("leave %d room\n", client.room.id)))

	delete(client.room.clients, client.conn)
	client.room = nil
}

func joinRoom(client *Client, roomID int) {
	server.m.RLock()
	room, exists := server.rooms[roomID]
	server.m.RUnlock()

	if !exists {
		client.conn.Write([]byte(fmt.Sprintf("%d room does not exist\n", roomID)))
		return
	}

	if len(room.clients) >= room.maxClient {
		client.conn.Write([]byte("room is full\n"))
		return
	}

	room.m.Lock()
	defer room.m.Unlock()
	room.clients[client.conn] = client
	client.room = room
	client.conn.Write([]byte(fmt.Sprintf("join room_%d \n", roomID)))
}

func createRoom(client *Client, name string, maxUsers int) {
	if client.user.Role != AdminRole {
		client.conn.Write([]byte("need admin role\n"))
		return
	}

	server.m.Lock()
	defer server.m.Unlock()

	atomicRoomID++
	room := &ChatRoom{
		id:        atomicRoomID,
		name:      name,
		clients:   make(map[net.Conn]*Client),
		maxClient: maxUsers,
		owner:     client.user,
	}

	server.rooms[atomicRoomID] = room
	client.conn.Write([]byte(fmt.Sprintf("create room: id %d\n", atomicRoomID)))
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

				client := &Client{conn: conn, user: user}
				server.m.Lock()
				server.clients[conn] = client
				server.m.Unlock()

				return user
			}
		case "/quit":
			return nil
		default:
			conn.Write([]byte("Not accepted command. You are not logged in. only support quit/login/register.\n"))
		}
	}
}

func handleConnection(conn net.Conn) {
	defer func() {
		closeConnection(conn)
	}()
	fmt.Printf("new client: %s\n", conn.RemoteAddr())

	conn.Write([]byte("Welcome to tiny chat server. Please register or login.\n" + getHelp()))

	var user *User
	reader := bufio.NewReader(conn)

	user = handleUserLogin(conn, reader)
	if user == nil {
		return
	}

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
		// 这里已经可以确保server.clients conn存在
		switch parts[0] {
		case "/list":
			listRoom(server.clients[conn])
		case "/quit":
			return
		case "/delete":
			if len(parts) != 2 {
				conn.Write([]byte("not correct command.\n"))
				continue
			}
			roomID, err := strconv.Atoi(parts[1])
			if err != nil {
				conn.Write([]byte(err.Error()))
				continue
			}
			deleteRoom(server.clients[conn], roomID)
		case "/join":
			if len(parts) != 2 {
				conn.Write([]byte("not correct command.\n"))
				continue
			}
			roomID, err := strconv.Atoi(parts[1])
			if err != nil {
				conn.Write([]byte(err.Error()))
				continue
			}

			joinRoom(server.clients[conn], roomID)
		case "/leave":
			leaveRoom(server.clients[conn])
		case "/send":
			if len(parts) != 2 {
				conn.Write([]byte("not correct command.\n"))
				continue
			}
			broadcastMessage(server.clients[conn], parts[1])
		case "/create":
			if len(parts) != 2 {
				conn.Write([]byte("not correct command.\n"))
				continue
			}
			createRoom(server.clients[conn], parts[1], server.roomMaxCapacity)
		case "/help":
			conn.Write([]byte(getHelp()))
		default:
			conn.Write([]byte("unknown command.\n"))
		}
	}
}

func broadcastMessage(client *Client, msg string) {
	if client.room == nil {
		client.conn.Write([]byte("you should join one room.\n"))
		return
	}
	fmt.Printf("%s broadcast msg to room%d\n", client.user.username, client.room.id)

	wrappedMsg := fmt.Sprintf("%s: %s\n", client.user.username, msg)
	client.room.m.RLock()
	defer client.room.m.RUnlock()
	for k := range client.room.clients {
		if k == client.conn {
			continue
		}
		k.Write([]byte(wrappedMsg))
	}
}
