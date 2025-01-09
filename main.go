package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const version = "0.0.1"

type StringList []string

func (s StringList) String() string {
	if len(s) == 0 {
		return ""
	}
	return strings.Join(s, ",")
}

func (s *StringList) Set(value string) error {
	*s = strings.Split(value, ",")
	return nil
}

type config struct {
	addr         string
	signers      []ssh.Signer
	allowedUsers map[string][]ssh.PublicKey
}

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)
	cfg, err := loadConfig()
	if err != nil {
		logger.Fatalf("Failed to load config: %v", err)
	}
	srv := ssh.Server{
		Addr: cfg.addr,
		Handler: func(s ssh.Session) {
			_, _ = io.WriteString(s, "Only port forwarding available...\n")
			_, _ = io.WriteString(s, "Use '-N' flag to not start terminal session\n")
		},
		HostSigners: cfg.signers,
		Version:     "SSHRelay_" + version,
		BannerHandler: func(ctx ssh.Context) string {
			return "" +
				"###################################################################\n" +
				"#                                                                 #\n" +
				"#  888888ba             dP                  dP       dP           #\n" +
				"#  88    `8b            88                  88       88           #\n" +
				"#  88     88 .d8888b. d8888P .d8888b. .d888b88 .d888b88 .d8888b.  #\n" +
				"#  88     88 88'  `88   88   88'  `88 88'  `88 88'  `88 88'  `88  #\n" +
				"#  88    .8P 88.  .88   88   88.  .88 88.  .88 88.  .88 88.  .88  #\n" +
				"#  8888888P  `88888P8   dP   `88888P8 `88888P8 `88888P8 `88888P'  #\n" +
				"#            __________ __  __   ____       __                    #\n" +
				"#           / ___/ ___// / / /  / __ \\___  / /___ ___  __         #\n" +
				"#           \\__ \\\\__ \\/ /_/ /  / /_/ / _ \\/ / __ `/ / / /         #\n" +
				"#          ___/ /__/ / __  /  / _, _/  __/ / /_/ / /_/ /          #\n" +
				"#         /____/____/_/ /_/  /_/ |_|\\___/_/\\__,_/\\__, /           #\n" +
				"#                                               /____/            #\n" +
				"###################################################################\n"
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			userKeys, ok := cfg.allowedUsers[ctx.User()]
			if !ok {
				return false
			}
			for _, userKey := range userKeys {
				if ssh.KeysEqual(key, userKey) {
					return true
				}
			}
			return false
		},
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			log.Println("Accepted forward", dhost, dport)
			return true
		}),
		// IdleTimeout: cfg.ClientAliveInterval,
		// MaxTimeout:  cfg.MaxTimeout,
		ChannelHandlers: map[string]ssh.ChannelHandler{
			// channel handler for local port forwarding
			"direct-tcpip": ssh.DirectTCPIPHandler,
			// add default session handler to show the info message.
			"session": ssh.DefaultSessionHandler,
		},
	}
	if err := srv.ListenAndServe(); !errors.Is(err, ssh.ErrServerClosed) {
		log.Fatalf("ListenAndServe failed: %v", err)
	}
	log.Println("Server closed")
}

func loadConfig() (config, error) {
	var (
		host     string
		port     uint
		hostKeys StringList = []string{"/etc/ssh/ssh_host_rsa_key"}
		users    StringList
		pubs     StringList
		pubPaths StringList
	)
	flag.StringVar(&host, "host", "0.0.0.0", "Hostname or IP address to listen on")
	flag.UintVar(&port, "port", 22, "Port to listen on")
	flag.Var(&hostKeys, "host-key", "Host key file (default \"/etc/ssh/ssh_host_rsa_key\")")
	flag.Var(&users, "user", "Allowed user")
	flag.Var(&pubs, "public-key", "Public key file for user")
	flag.Var(&pubPaths, "public-key-path", "Path to public key file for user")
	flag.Parse()
	if port > 65535 {
		return config{}, fmt.Errorf("invalid port number: %d", port)
	}
	signers, err := prepareSigners(hostKeys)
	if err != nil {
		return config{}, fmt.Errorf("failed to prepare signers: %w", err)
	}
	allowedUsers, err := allowedUsersPubKeys(users, pubs, pubPaths)
	if err != nil {
		return config{}, fmt.Errorf("failed to prepare allowed users: %w", err)
	}
	c := config{
		addr:         net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)),
		signers:      signers,
		allowedUsers: allowedUsers,
	}
	return c, nil
}

func allowedUsersPubKeys(users, pubs, pubPaths []string) (map[string][]ssh.PublicKey, error) {
	if len(pubs) > 0 && len(pubPaths) > 0 {
		return nil, errors.New("cannot use both public-key and public-key-path")
	}
	pubsData := make([][]byte, 0, len(users))
	switch {
	case len(pubs) > 0:
		for _, pub := range pubs {
			pubsData = append(pubsData, []byte(pub))
		}
	case len(pubPaths) > 0:
		for _, path := range pubPaths {
			pubData, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("failed to read public key file: %w", err)
			}
			pubsData = append(pubsData, pubData)
		}
	}
	if len(users) != len(pubsData) {
		return nil, errors.New("number of users and public keys does not match")
	}
	allowedUsers := make(map[string][]ssh.PublicKey)
	for i, user := range users {
		pubKey, _, _, _, err := gossh.ParseAuthorizedKey(pubsData[i])
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		allowedUsers[user] = append(allowedUsers[user], pubKey)
	}
	return allowedUsers, nil
}

func prepareSigners(hostKeys []string) ([]ssh.Signer, error) {
	if len(hostKeys) == 0 {
		hostKeys = StringList{"/etc/ssh/ssh_host_rsa_key"}
	}
	var signers []ssh.Signer
	for _, hostKey := range hostKeys {
		keyData, err := os.ReadFile(hostKey)
		if err != nil {
			return nil, fmt.Errorf("failed to read host key file: %w", err)
		}
		signer, err := gossh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		signers = append(signers, signer)
	}
	return signers, nil
}
