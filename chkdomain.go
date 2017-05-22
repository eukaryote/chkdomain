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
	"path/filepath"
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

// Run job and send result to 'Job.results'.
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

// Create jobs (without starting them).
func makeJobs(jobs chan<- Job, domains []string, results chan<- Result) {
	for _, domain := range domains {
		jobs <- Job{domain, results}
	}
	close(jobs)
}

// Start all jobs running.
func runJobs(done chan<- struct{}, jobs <-chan Job) {
	for job := range jobs {
		job.Run()
	}
	done <- struct{}{}
}

// Wait for all jobs to complete.
func waitJobs(done <-chan struct{}, results chan Result, workers int) {
	for i := 0; i < workers; i++ {
		<-done
	}
	close(results)
}

// Process results as they are ready.
func processResults(results <-chan Result, debug bool) {
	for result := range results {
		if result.err != nil {
			fmt.Printf("%s: %s\n", result.domain, result.err)
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

	}
}

func usage(status int) {
	fmt.Printf("usage: %s [-h] DOMAIN [DOMAIN]*\n\n",
		filepath.Base(os.Args[0]))
	fmt.Printf("If a single '-' param is given, domains will be read ")
	fmt.Printf("from stdin, one domain per line.\n\n")
	fmt.Printf("Domain names that are available will be printed to stdout.\n")
	os.Exit(status)
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
	// At least 1 arg is required, so print usage and fail if none given.
	if len(os.Args) < 2 {
		usage(1)
	}

	debug := flag.Bool("debug", false, "print debug info (all results, with times)")
	help := flag.Bool("help", false, "show usage info")
	flag.Parse()

	if *help {
		usage(0)
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
	}

	// Prepare jobs and then start them all running and wait for results
	// before printing results to stdout.
	jobs := make(chan Job, numDomains)
	results := make(chan Result, numDomains)
	done := make(chan struct{}, numDomains)

	go makeJobs(jobs, domains, results)

	for i := 0; i < numDomains; i++ {
		go runJobs(done, jobs)
	}
	go waitJobs(done, results, numDomains)
	processResults(results, *debug)
}
