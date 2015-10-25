package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"reflect"
	"unsafe"

	"golang.org/x/crypto/ssh"
)

func main() {
	cc := &ssh.CertChecker{
		UserKeyFallback: func(conn ssh.ConnMetadata, pk ssh.PublicKey) (p *ssh.Permissions, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("%v", r)
				}
			}()
			user := conn.User()
			if pktype := pk.Type(); pktype != "ssh-rsa" {
				return nil, fmt.Errorf("Require ssh-rsa public key, got %q", pktype)
			}

			// Thanks FiloSottile/whosthere
			k := (*rsa.PublicKey)(unsafe.Pointer(reflect.ValueOf(pk).Elem().FieldByName("N").UnsafeAddr()))
			modulus := k.N
			_ = conn.SessionID()
			cver := conn.ClientVersion()
			_ = conn.ServerVersion()
			raddr := conn.RemoteAddr()
			_ = conn.LocalAddr()

			fmt.Printf(
				"cc.ukf: user=%q, modulus=%v, cver=%s, raddr=%v\n",
				user, modulus, cver, raddr,
			)

			return &ssh.Permissions{}, nil
		},
	}

	config := &ssh.ServerConfig{
		// NoClientAuth:      true,
		PublicKeyCallback: cc.Authenticate,
		AuthLogCallback: func(conn ssh.ConnMetadata, method string, err error) {
			fmt.Printf("conn=%#v, method=%q, err=%v\n", conn, method, err)
		},
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	privateBytes, err := ioutil.ReadFile("/root/.ssh/id_rsa") // <-- yeah
	if err != nil {
		log.Fatal("Failed to load private key (/root/.ssh/id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		log.Fatalf("Failed to listen on 22 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 22...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		log.Printf("Connection: %#v\n", sshConn)
		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, _, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	defer connection.Close()

	connection.Write([]byte("Hello!\n"))
}
