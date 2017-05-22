// chkdomain runs whois lookups against one or more domain names and prints
// those that are available to stdout.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	// Regex for detecting whois response indicating domain is available
	availableRE = regexp.MustCompile(`\b(is not registered|is available|no match for|not found)\b`)
	// Regex for validating a domain, to prevent things like '--foo' from being queried
	domainRE = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-\.]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$`)
	// Time in ms past epoch when program started
	startMS = time.Now().UnixNano() / int64(time.Millisecond)
)

// The result of a whois check for a single domain.
type Result struct {
	domain    string
	output    string
	available bool
	err       error
}

// A currently running job to lookup info for a single domain.
type Job struct {
	domain  string
	results chan<- Result
}

// Run job and send result to 'results' channel.
func (job Job) Run() {
	result := Result{domain: job.domain}
	if whoisOutput, err := whois(result.domain); err != nil {
		result.err = err
	} else {
		result.output = whoisOutput
		result.available = isDomainAvailable(whoisOutput)
	}
	job.results <- result
}

// Answer whether domain appears to be available based on whois text result.
func isDomainAvailable(whoisText string) bool {
	return availableRE.FindString(strings.ToLower(whoisText)) != ""
}

// Answer whether domain is valid by validating against domainRE regex.
func isDomainValid(domain string) bool {
	return !!domainRE.MatchString(domain)
}

// Get the whois server (including port) for querying a given domain.
func getWhoisServer(domain string) string {
	segments := strings.Split(domain, ".")
	tld := segments[len(segments)-1]
	if len(segments) > 2 {
		tld = segments[len(segments)-2] + "." + tld
	}
	return tld + ".whois-servers.net:43"
}

// Run a whois check for the given domain, returning the non-empty string
// result of the lookup (and nil) on success, or an empty string and error
// on failure.
func whois(domain string) (string, error) {
	if !isDomainValid(domain) {
		return "", errors.New(fmt.Sprintf("invalid domain: %s", domain))
	}
	whoisServer := getWhoisServer(domain)
	if conn, connErr := net.Dial("tcp", whoisServer); connErr != nil {
		msg := fmt.Sprint("error connecting to %v: %v", whoisServer, connErr)
		return "", errors.New(msg)
	} else {
		if _, wrtErr := conn.Write([]byte(domain + "\r\n")); wrtErr != nil {
			return "", wrtErr
		}
		buf := make([]byte, 1024)
		res := []byte{}
		for {
			if numBytes, readErr := conn.Read(buf); numBytes == 0 && readErr != io.EOF {
				return "", readErr
			} else {
				res = append(res, buf[0:numBytes]...)
				if readErr == io.EOF {
					break
				}
			}
		}
		return string(res), nil
	}
}

// Process results as they are ready, closing 'done' after all expected
// results have been processed (based on numDomains).
func processResults(results chan Result, numDomains int, done chan struct{}, debug bool) {
	processed := 0
	for result := range results {
		processed += 1
		if result.err != nil {
			fmt.Printf("%s\n", result.err)
			continue
		}
		if debug {
			fmt.Printf("[%d]\t", (time.Now().UnixNano()/int64(time.Millisecond))-startMS)
		}
		if result.available {
			if debug {
				fmt.Printf("AVAILABLE\t")
			}
			fmt.Println(result.domain)
		} else {
			if debug {
				fmt.Printf("UNAVAILABLE\t")
				fmt.Println(result.domain)
			}
		}
		if processed >= numDomains {
			close(done)
			return
		}
	}
}

func readLines() ([]string, error) {
	bio := bufio.NewReader(os.Stdin)
	lines := make([]string, 0, 8)
	for {
		line, err := bio.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return lines, err
			}
		}
		lines = append(lines, line[:len(line)-1])
	}
	return lines, nil
}

func main() {

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: chkdomain [options] <DOMAIN> [DOMAIN...]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n  DOMAIN domain name to check, or - to read from stdin (one per line)")
		os.Exit(1)
	}

	debug := flag.Bool("debug", false, "print debug info (all results, with times)")
	flag.Parse()

	// At least 1 arg is required, so print usage and fail if none given.
	if len(os.Args) < 2 {
		flag.Usage()
	}

	domains := flag.Args()
	numDomains := len(domains)

	// If there's just one arg, check if it's '-' to indicate that
	// domains will be provided one-per-line via stdin, and read them if so.
	if numDomains == 1 && domains[0] == "-" {
		fileDomains, err := readLines()
		if err != nil {
			fmt.Printf("error reading domains from stdin: %s\n", err)
			os.Exit(1)
		}
		domains = fileDomains
		numDomains = len(domains)
	}

	results := make(chan Result, numDomains)
	done := make(chan struct{})

	// Run all jobs concurrently
	for _, domain := range domains {
		go Job{domain, results}.Run()
	}

	// Process results, waiting on 'done' to be closed after all
	// expected results have been processed.
	go processResults(results, numDomains, done, *debug)
	<-done
}
