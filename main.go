package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/bep/simplecobra"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const version = "0.0.1"

type rootCmd struct {
	flags cmdFlags
	cfg   config
}

func (r *rootCmd) Name() string { return "sshrelay" }

func (r *rootCmd) Commands() []simplecobra.Commander {
	return []simplecobra.Commander{}
}

func main() {
	ex, err := simplecobra.New(&rootCmd{})
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}

	log.Printf("args: %v", os.Args[1:])
	if c, err := ex.Execute(context.Background(), os.Args[1:]); err != nil {
		if simplecobra.IsCommandError(err) {
			_ = c.CobraCommand.Help()
			fmt.Println()
			fmt.Println(err)
			os.Exit(2)
		}
		log.Fatal(err)
	}
}

func (r *rootCmd) Run(ctx context.Context, _ *simplecobra.Commandeer, _ []string) error {
	// logger := log.New(os.Stderr, "", log.LstdFlags)
	srv := ssh.Server{
		Addr: r.cfg.addr,
		Handler: func(s ssh.Session) {
			_, _ = io.WriteString(s, "Only port forwarding available...\n")
			_, _ = io.WriteString(s, "Use '-N' flag to not start terminal session\n")
		},
		HostSigners: r.cfg.signers,
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
			userKeys, ok := r.cfg.allowedUsers[ctx.User()]
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
	return runServer(ctx, &srv)
}

func runServer(_ context.Context, srv *ssh.Server) error {
	if srv.Addr == "" {
		srv.Addr = ":22"
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs)

	log.Printf("Listener addr: %s", srv.Addr)

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", srv.Addr, err)
	}
	defer ln.Close()

	log.Printf("Listening on %s\n", ln.Addr().String())

	go closeListener(sigs, ln)
	if err := srv.Serve(ln); !errors.Is(err, ssh.ErrServerClosed) {
		return fmt.Errorf("ListenAndServe failed: %v", err)
	}
	log.Println("Server closed")
	return nil
}

func closeListener(sigs <-chan os.Signal, ln net.Listener) {
	for sig := range sigs {
		// log.Printf("RECEIVED SIGNAL: %s", sig)
		if sig == syscall.SIGTERM || sig == syscall.SIGINT {
			if err := ln.Close(); err != nil {
				log.Printf("Failed to close listener: %v", err)
				os.Exit(1)
			}
		}
	}
}

type config struct {
	addr         string
	signers      []ssh.Signer
	allowedUsers map[string][]ssh.PublicKey
}

func (r *rootCmd) PreRun(_, _ *simplecobra.Commandeer) error {
	log.Printf("PreRun: %#v\n", r.flags)

	if r.flags.port > 65535 {
		return fmt.Errorf("invalid port number: %d", r.flags.port)
	}
	signers, err := prepareSigners(r.flags.hostKeys)
	if err != nil {
		return fmt.Errorf("failed to prepare signers: %w", err)
	}
	allowedUsers, err := allowedUsersPubKeys(r.flags.users, r.flags.pubs, r.flags.pubPaths)
	if err != nil {
		return fmt.Errorf("failed to prepare allowed users: %w", err)
	}
	r.cfg = config{
		addr:         net.JoinHostPort(r.flags.host, strconv.FormatUint(uint64(r.flags.port), 10)),
		signers:      signers,
		allowedUsers: allowedUsers,
	}
	return nil
}

type cmdFlags struct {
	host     string
	port     uint
	hostKeys []string
	users    []string
	pubs     []string
	pubPaths []string
}

func (r *rootCmd) Init(c *simplecobra.Commandeer) error {
	flags := c.CobraCommand.PersistentFlags()
	flags.StringVar(&r.flags.host, "host", "0.0.0.0", "Hostname or IP address to listen on")
	flags.UintVar(&r.flags.port, "port", 22, "Port to listen on")
	flags.StringSliceVar(&r.flags.hostKeys, "host-key", []string{"/etc/ssh/ssh_host_rsa_key"}, "Host key file")
	flags.StringSliceVar(&r.flags.users, "user", nil, "Allowed user")
	flags.StringSliceVar(&r.flags.pubs, "public-key", nil, "Public key file for user")
	flags.StringSliceVar(&r.flags.pubPaths, "public-key-path", nil, "Path to public key file for user")
	return nil
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
