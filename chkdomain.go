package main

import (
	"errors"
	"fmt"
	"net"
	"os"
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
	workers     = 32
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
		defer conn.Close()
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
		result.output = string(res)
		result.available = isDomainAvailable(result.output)
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

func waitJobs(done <-chan struct{}, results chan Result) {
	for i := 0; i < workers; i++ {
		<-done
	}
	close(results)
}

func processResults(results <-chan Result) {
	for result := range results {
		if result.err != nil {
			fmt.Printf("'%s' error: %s\n", result.domain, result.err)
		} else {
			msg := result.domain
			if result.available {
				msg += " IS AVAILABLE"
			} else {
				msg += " IS NOT AVAILABLE"
			}
			fmt.Println(msg)
		}
	}
}

func main() {
	runtime.GOMAXPROCS(workers)
	if len(os.Args) == 1 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Printf("usage: %s DOMAIN ...\n", os.Args[0])
		os.Exit(1)
	}
	domains := os.Args[1:]

	jobs := make(chan Job, workers)
	results := make(chan Result, minimum(100, len(domains)))
	done := make(chan struct{}, workers)

	go mkJobs(jobs, domains, results)

	for i := 0; i < workers; i++ {
		go runJobs(done, jobs)
	}
	go waitJobs(done, results)
	processResults(results)
}
