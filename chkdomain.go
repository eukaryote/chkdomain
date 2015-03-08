package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

type WhoisResult struct {
	domain string
	output string
}

func whois(domain string) (WhoisResult, error) {
	segments := strings.Split(domain, ".")
	tld := segments[len(segments)-1]
	server := tld + ".whois-servers.net:43"
	conn, err := net.Dial("tcp", server)
	if err != nil {
		return WhoisResult{}, err
	}
	conn.Write([]byte(domain + "\r\n"))
	buf := make([]byte, 1024)
	res := []byte{}
	for {
		numbytes, err := conn.Read(buf)
		sbuf := buf[0:numbytes]
		res = append(res, sbuf...)
		if err != nil {
			break
		}
	}
	conn.Close()
	return WhoisResult{domain: domain, output: string(res)}, nil
}

var availableRE = regexp.MustCompile(`\b(is not registered|is available|no match for)\b`)

func isAvailable(whoisOut string) bool {
	return availableRE.FindString(strings.ToLower(whoisOut)) != ""
}

func main() {
	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Printf("usage: %s DOMAIN ...\n", os.Args[0])
		os.Exit(1)
	}
	domainRE := regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$`)
	for _, domain := range os.Args[1:] {
		if domainRE.MatchString(domain) {
			res, err := whois(domain)
			if err != nil {
				fmt.Printf("error [%s]: %s", domain, err)
			} else {
				msg := "IS"
				if isAvailable(res.output) {
					msg += " AVAILABLE"
				} else {
					msg += " NOT AVAILABLE"
				}
				fmt.Printf("%s %s\n", domain, msg)
			}
		} else {
			fmt.Printf("invalid domain: %s\n", domain)
		}
	}

}
