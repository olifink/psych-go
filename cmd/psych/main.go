package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"psych/internal/client"
	"psych/internal/relay"
)

const defaultRelay = "ws://127.0.0.1:8080/ws"

var version = "dev"

func printUsage() {
	fmt.Fprintf(os.Stderr, `PSYCH - End-to-End Encrypted Terminal Pipe & Relay (%s)

Usage:
  psych <command> [arguments]

Commands:
  server   Start an in-memory blind WebSocket relay
  session  Initiate a new encrypted session and display QR code (Initiator)
  join     Connect to an existing encrypted session (Joiner)
  send     Pipe data from stdin to an encrypted session and exit
  recv     Receive a single payload and output to stdout
  version  Display version information

Run 'psych <command> --help' for details on a specific command.
`, version)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "server":
		runServer(os.Args[2:])
	case "session":
		runSession(os.Args[2:])
	case "join":
		runJoin(os.Args[2:])
	case "send":
		runSend(os.Args[2:])
	case "recv":
		runRecv(os.Args[2:])
	case "-v", "--version", "version":
		fmt.Printf("psych version %s\n", version)
		os.Exit(0)
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	host := fs.String("host", "0.0.0.0", "Bind address for relay server")
	port := fs.Int("port", 8080, "Port for relay server")
	_ = fs.Parse(args)

	srv := relay.NewServer()

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nShutting down relay server...")
		_ = srv.Close()
		os.Exit(0)
	}()

	fmt.Fprintf(os.Stderr, "Starting PSYCH relay on %s:%d\n", *host, *port)
	fmt.Fprintf(os.Stderr, "WebSocket endpoint: ws://%s:%d/ws?sid=<sid>\n", *host, *port)
	fmt.Fprintf(os.Stderr, "Health check endpoint: http://%s:%d/healthz\n", *host, *port)

	if err := srv.Start(*host, *port); err != nil {
		fmt.Fprintf(os.Stderr, "Relay server failed: %v\n", err)
		os.Exit(1)
	}
}

func runSession(args []string) {
	fs := flag.NewFlagSet("session", flag.ExitOnError)
	relayURL := fs.String("relay", defaultRelay, "WebSocket relay endpoint")
	_ = fs.Parse(args)

	if err := client.StartInitiatorSession(*relayURL, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Session failed: %v\n", err)
		os.Exit(1)
	}
}

func rearrangeArgs(args []string) []string {
	var flags []string
	var positionals []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positionals = append(positionals, arg)
		}
	}
	return append(flags, positionals...)
}

func runJoin(args []string) {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	pub := fs.String("pub", "", "Initiator X25519 public key (hex, if passing raw SID)")
	relayURL := fs.String("relay", defaultRelay, "WebSocket relay endpoint")
	_ = fs.Parse(rearrangeArgs(args))

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing pairing code, URI, or session ID argument")
		fmt.Fprintln(os.Stderr, "Usage: psych join <code-or-uri-or-sid> [--pub <initiator-pubkey>] [--relay <relay-url>]")
		os.Exit(1)
	}

	target := fs.Arg(0)
	if err := client.StartJoinerSession(target, *relayURL, *pub, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Join failed: %v\n", err)
		os.Exit(1)
	}
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	pub := fs.String("pub", "", "Initiator X25519 public key (hex, if passing raw SID)")
	relayURL := fs.String("relay", defaultRelay, "WebSocket relay endpoint")
	_ = fs.Parse(rearrangeArgs(args))

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: missing pairing code, URI, or session ID argument")
		fmt.Fprintln(os.Stderr, "Usage: psych send <code-or-uri-or-sid> [--pub <initiator-pubkey>] [--relay <relay-url>]")
		os.Exit(1)
	}

	target := fs.Arg(0)
	if err := client.RunSend(target, *relayURL, *pub, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "Send failed: %v\n", err)
		os.Exit(1)
	}
}

func runRecv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	relayURL := fs.String("relay", defaultRelay, "WebSocket relay endpoint")
	_ = fs.Parse(args)

	if err := client.RunRecv(*relayURL, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "Recv failed: %v\n", err)
		os.Exit(1)
	}
}
