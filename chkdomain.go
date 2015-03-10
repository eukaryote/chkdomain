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

func minimum(x, y int) int {
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

func (job Job) Run() {
	domain := job.domain
	result := Result{domain: domain}
	if !isDomainValid(domain) {
		result.err = errors.New("invalid domain")
	} else {
		conn, err := net.Dial("tcp", getWhoisServer(domain))
		if err != nil {
			result.err = err
			return
		}
		_, werr := conn.Write([]byte(domain + "\r\n"))
		if werr != nil {
			fmt.Printf("Write error: %s\n", werr)
		}
		buf := make([]byte, 1024)
		res := []byte{}
		for {
			numbytes, err := conn.Read(buf)
			if numbytes == 0 && err != io.EOF {
				result.err = err
				break
			}
			sbuf := buf[0:numbytes]
			res = append(res, sbuf...)
			if err != nil {
				break
			}
		}
		result.output = string(res)
		result.available = isDomainAvailable(result.output)
		conn.Close()
	}
	job.results <- result
}

func mkJobs(jobs chan<- Job, domains []string, results chan<- Result) {
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
	workers := minimum(100, len(domains))
	runtime.GOMAXPROCS(workers)

	jobs := make(chan Job, workers)
	results := make(chan Result, workers)
	done := make(chan struct{}, workers)

	go mkJobs(jobs, domains, results)

	for i := 0; i < workers; i++ {
		go runJobs(done, jobs)
	}
	go waitJobs(done, results, workers)
	processResults(results)
}
