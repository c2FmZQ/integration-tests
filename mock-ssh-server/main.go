package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				log.Printf("PublicKeyCallback: PublicKey is not a cert (%T)", key)
				return nil, fmt.Errorf("not a certificate")
			}

			caURL := "https://ssh.example.com/ssh/ca"
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			}
			resp, err := client.Get(caURL)
			if err != nil {
				log.Printf("PublicKeyCallback: GET %s: %v", caURL, err)
				return nil, err
			}
			defer resp.Body.Close()
			caPublicKey, err := io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("PublicKeyCallback: ReadAll: %v", err)
				return nil, err
			}

			checker := ssh.CertChecker{}
			publicKey, _, _, _, err := ssh.ParseAuthorizedKey(caPublicKey)
			if err != nil {
				log.Printf("PublicKeyCallback: ParseAuthorizedKey: %v", err)
				return nil, err
			}
			checker.IsUserAuthority = func(auth ssh.PublicKey) bool {
				return string(auth.Marshal()) == string(publicKey.Marshal())
			}

			if err := checker.CheckCert(conn.User(), cert); err != nil {
				log.Printf("PublicKeyCallback: CheckCert: %v", err)
				return nil, err
			}
			return &ssh.Permissions{}, nil
		},
	}

	privateBytes, err := os.ReadFile("mock_ssh_server_key")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	config.AddHostKey(private)

	listener, err := net.Listen("tcp", "0.0.0.0:2222")
	if err != nil {
		log.Fatalf("Failed to listen on 2222: %v", err)
	}
	log.Printf("Listening on %s", listener.Addr())

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection: %v", err)
			continue
		}
		log.Printf("Accepted new connection from %s", conn.RemoteAddr())

		_, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			log.Printf("Failed to handshake: %v", err)
			continue
		}
		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			log.Print("Started new session")
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Printf("Could not accept channel: %v", err)
				continue
			}

			go func(in <-chan *ssh.Request) {
				for req := range in {
					switch req.Type {
					case "shell":
						req.Reply(true, nil)
					case "pty-req":
						req.Reply(true, nil)
					}
				}
			}(requests)

			go func() {
				defer channel.Close()
				for i := range 10 {
					channel.Write([]byte(fmt.Sprintf("hello %d\n", 10-i)))
					time.Sleep(1 * time.Second)
				}
				channel.Write([]byte("bye\n"))
			}()
		}
	}
}
