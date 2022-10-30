// Grabs certificates from a remote source
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	VERSION = "v1.0.1"
)

// holds the args supplied to the program
type commandArgs struct {
	Timeout      int
	IncludeChain bool
	UseDER       bool
	OutFile      string
}

// Display usage then exit
func usage() {
	usage := `Usage: ` + os.Args[0] + ` [Options] host:port`
	usage += `

Grabs x509 certificate(s) from a remote host, format will default to PEM. 
  ` + VERSION + ` Mike Cromwell 2022

Options:
  -h, --help    show this help message and exit
  -c, --chain   include the chain
  -d, --der     write in DER format instead of PEM
  -w, --wait    wait timeout for connection in seconds
  -o, --out     output to file instead of stdout

`
	fmt.Fprint(flag.CommandLine.Output(), usage)
	os.Exit(1)
}

// Helper func to handle errors that should exit the program
func handlErrFatal(err error) {
	if err != nil {
		log.Fatal("[!] ", err)
	}
}

// Check that the args passed are valid, returns either the host string or shows usage
func checkArgs() string {
	if len(flag.Args()) < 1 {
		usage()
	}

	netAddr := flag.Arg(0)
	_, strPort, ok := strings.Cut(netAddr, ":")
	if !ok {
		usage()
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		usage()
	}
	if port < 1 {
		usage()
	}

	return netAddr
}

// Makes a connection to the remote host and returns the certs and closes the connection
func getCerts(host string, args commandArgs) []*x509.Certificate {
	log.Printf("[*] retrieving cert(s) from %s", host)
	// not bothered about verification of cert
	cfg := &tls.Config{InsecureSkipVerify: true}
	dialer := &net.Dialer{Timeout: time.Duration(args.Timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", host, cfg)
	handlErrFatal(err)
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates
}

// Writes the out bytes into a file, default is stdout
func writeOutput(out []byte, args commandArgs) {
	fileOut := os.Stdout
	if len(args.OutFile) > 0 {
		f, err := os.OpenFile(args.OutFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0660)
		handlErrFatal(err)
		defer f.Close()
		fileOut = f
	}
	fileOut.Write(out)
}

// Processes the certs passed
func processCerts(certs []*x509.Certificate, args commandArgs) {
	// only use the first item in the slice
	if !args.IncludeChain {
		certs = []*x509.Certificate{certs[0]}
	}

	log.Printf("[+] retrieved %d cert(s)", len(certs))
	for _, cert := range certs {
		if args.UseDER {
			// Write the Raw DER
			writeOutput(cert.Raw, args)
			continue
		}

		// convert to PEM then write
		pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}
		writeOutput(pem.EncodeToMemory(pemBlock), args)
	}
}

func main() {
	args := commandArgs{}
	log.SetFlags(0)
	log.SetPrefix("")

	// setup and process args
	flag.IntVar(&args.Timeout, "w", 20, "wait timeout")
	flag.IntVar(&args.Timeout, "wait", 20, "wait timeout")
	flag.BoolVar(&args.IncludeChain, "c", false, "include cetificate chain")
	flag.BoolVar(&args.IncludeChain, "chain", false, "include cetificate chain")
	flag.BoolVar(&args.UseDER, "d", false, "use DER format")
	flag.BoolVar(&args.UseDER, "der", false, "use DER format")
	flag.StringVar(&args.OutFile, "o", "", "output file to write to otherwise uses stdout")
	flag.StringVar(&args.OutFile, "out", "", "output file to write to otherwise uses stdout")
	flag.Usage = usage
	flag.Parse()
	host := checkArgs()
	certs := getCerts(host, args)
	processCerts(certs, args)
}
