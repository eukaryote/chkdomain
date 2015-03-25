package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

type Job struct {
	domain  string
	results chan<- Result
}

type Result struct {
	domain    string
	output    string
	available bool
	err       error
}

var (
	availableRE = regexp.MustCompile(`\b(is not registered|is available|no match for|not found)\b`)
	domainRE    = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-\.]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,}$`)
)

func minInt(x, y int) int {
	if y < x {
		return y
	} else {
		return x
	}
}

func isDomainAvailable(whoisText string) bool {
	return availableRE.FindString(strings.ToLower(whoisText)) != ""
}

func isDomainValid(domain string) bool {
	return !!domainRE.MatchString(domain)
}

func getWhoisServer(domain string) string {
	segments := strings.Split(domain, ".")
	tld := segments[len(segments)-1]
	if len(segments) > 2 {
		tld = segments[len(segments)-2] + "." + tld
	}
	return tld + ".whois-servers.net:43"
}

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

func makeJobs(jobs chan<- Job, domains []string, results chan<- Result) {
	for _, domain := range domains {
		jobs <- Job{domain, results}
	}
	close(jobs)
}

func runJobs(done chan<- struct{}, jobs <-chan Job) {
	for job := range jobs {
		job.Run()
	}
	done <- struct{}{}
}

func waitJobs(done <-chan struct{}, results chan Result, workers int) {
	for i := 0; i < workers; i++ {
		<-done
	}
	close(results)
}

func processResults(results <-chan Result) {
	for result := range results {
		if result.err != nil {
			fmt.Printf("%s: %s\n", result.domain, result.err)
		} else if result.available {
			fmt.Println(result.domain)
		}
	}
}

func usage(status int) {
	fmt.Printf("usage: %s [-h] DOMAIN [DOMAIN]*\n",
		filepath.Base(os.Args[0]))
	fmt.Printf("If a single '-' param is given, domains will be read ")
	fmt.Printf("from stdin, one domain per line.\n")
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
	if len(os.Args) == 1 {
		usage(1)
	} else if os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage(0)
	}
	domains := os.Args[1:]
	if len(domains) == 1 && domains[0] == "-" {
		fileDomains, err := readLines()
		if err != nil {
			fmt.Printf("error reading domains from stdin: %s\n", err)
			os.Exit(1)
		}
		domains = fileDomains
	}
	workers := minInt(100, len(domains))
	runtime.GOMAXPROCS(workers)

	jobs := make(chan Job, workers)
	results := make(chan Result, workers)
	done := make(chan struct{}, workers)

	go makeJobs(jobs, domains, results)

	for i := 0; i < workers; i++ {
		go runJobs(done, jobs)
	}
	go waitJobs(done, results, workers)
	processResults(results)
}
