// network-analyzer collects data about the machine it is running on and its
// network connection to help diagnose routing, DNS, and other issues to
// MaxMind servers.
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"
)

const (
	host        = "geoip.maxmind.com"
	zipFileName = "mm-network-analysis.zip"
)

type zipFile struct {
	name     string
	contents []byte
}

type analyzer struct {
	zipWriter *zip.Writer
	zipFile   *os.File

	// We use mutexes as it is a bit easier to handle writing
	// in the main go routine
	errorsMutex sync.Mutex
	errors      []error

	zipFilesMutex sync.Mutex
	zipFiles      []*zipFile
}

func main() {
	a, err := newAnalyzer()
	if err != nil {
		log.Println(err)
	}

	//nolint: lll
	tasks := []func(){
		// Ideally, we would just be doing these using Go's httptrace so that
		// they don't require curl, but this is good enough for now.
		//nolint:goconst //preexisting
		a.createStoreCommand("https-"+host+"-curl-ipv4.txt", "curl", "-4", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "https://"+host),
		//nolint:goconst //preexisting
		a.createStoreCommand("http-"+host+"-curl-ipv4.txt", "curl", "-4", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "http://"+host),
		a.createStoreCommand("https-"+host+"-curl-ipv6.txt", "curl", "-6", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "https://"+host),
		a.createStoreCommand("http-"+host+"-curl-ipv6.txt", "curl", "-6", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "http://"+host),

		// Get Cloudflare /cdn-cgi/trace output to determine colo endpoint
		//nolint:goconst //preexisting
		a.createStoreCommand("https-"+host+"-cdn-cgi-trace-ipv4.txt", "curl", "-4", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "https://"+host+"/cdn-cgi/trace"),
		a.createStoreCommand("http-"+host+"-cdn-cgi-trace-ipv4.txt", "curl", "-4", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "http://"+host+"/cdn-cgi/trace"),

		a.createStoreCommand("https-"+host+"-cdn-cgi-trace-ipv6.txt", "curl", "-6", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "https://"+host+"/cdn-cgi/trace"),
		a.createStoreCommand("http-"+host+"-cdn-cgi-trace-ipv6.txt", "curl", "-6", "--trace-time", "--trace-ascii", "-", "--user-agent", os.Args[0], "http://"+host+"/cdn-cgi/trace"),

		// Sanity check DNS resolution
		a.createStoreCommand(host+"-dig.txt", "dig", "-4", "+all", host, "A", host, "AAAA"),
		a.createStoreCommand(host+"-dig-google.txt", "dig", "-4", "+all", "@8.8.8.8", host, "A", host, "AAAA"),
		a.createStoreCommand(host+"-dig-google-trace.txt", "dig", "-4", "+all", "+trace", "@8.8.8.8", host, "A", host, "AAAA"),

		// CF support want this, but there are multiple boxes in the pool
		// so no guarantee we will see the same results as a customer
		// or hit a broken NS, if there is one
		a.createStoreCommand(host+"-dig-cloudflare-josh.txt", "dig", "-4", host, "@josh.ns.cloudflare.com", "+nsid"),
		a.createStoreCommand(host+"-dig-cloudflare-kim.txt", "dig", "-4", host, "@kim.ns.cloudflare.com", "+nsid"),

		// rfc4892 - gives geographic region
		a.createStoreCommand("dig-cloudflare-josh-rfc4892.txt", "dig", "-4", "CH", "TXT", "id.server", "@josh.ns.cloudflare.com", "+nsid"),
		a.createStoreCommand("dig-cloudflare-kim-rfc4892.txt", "dig", "-4", "CH", "TXT", "id.server", "@kim.ns.cloudflare.com", "+nsid"),

		// CF support want this, too. Don't see what it's useful for
		// unless we have customers using this service
		// and they happen to hit the same box in the pool
		a.createStoreCommand("dig-cloudflare.txt", "dig", "-4", "@1.1.1.1", "CH", "TXT", "hostname.cloudflare", "+short"),

		a.createStoreCommand("ip-addr.txt", "ip", "addr"),
		a.createStoreCommand("ip-route.txt", "ip", "route"),

		a.createStoreCommand(host+"-ping-ipv4.txt", "ping", "-4", "-c", "30", host),
		a.createStoreCommand(host+"-ping-ipv6.txt", "ping", "-6", "-c", "30", host),
		a.createStoreCommand(host+"-tracepath.txt", "tracepath", host),
		a.addIP,
		a.addResolvConf,
	}

	tasks = append(tasks, a.mtrCommands()...)

	var wg sync.WaitGroup
	for _, task := range tasks {
		wg.Add(1)
		go func(task func()) {
			task()
			wg.Done()
		}(task)
	}

	wg.Wait()

	err = a.addErrors()
	if err != nil {
		log.Println(err)
	}

	err = a.writeFiles()
	if err != nil {
		log.Println(err)
	}

	err = a.close()
	if err != nil {
		log.Println(err)
	}
}

func newAnalyzer() (*analyzer, error) {
	f, err := os.OpenFile(zipFileName, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", zipFileName, err)
	}

	return &analyzer{
		zipWriter: zip.NewWriter(f),
		zipFile:   f,
	}, nil
}

func (a *analyzer) close() error {
	err := a.zipWriter.Close()
	if err != nil {
		return fmt.Errorf("closing zip file writer: %w", err)
	}
	err = a.zipFile.Close()
	if err != nil {
		return fmt.Errorf("closing zip file: %w", err)
	}
	return nil
}

func (a *analyzer) storeFile(name string, contents []byte) {
	a.zipFilesMutex.Lock()
	a.zipFiles = append(a.zipFiles, &zipFile{name: name, contents: contents})
	a.zipFilesMutex.Unlock()
}

func (a *analyzer) storeError(err error) {
	a.errorsMutex.Lock()
	a.errors = append(a.errors, err)
	a.errorsMutex.Unlock()
}

func (a *analyzer) writeFile(zf *zipFile) error {
	header := &zip.FileHeader{
		Name:     zf.name,
		Method:   zip.Deflate,
		Modified: time.Now(),
	}
	w, err := a.zipWriter.CreateHeader(header)
	if err != nil {
		return fmt.Errorf("creating %s in zip file: %w", zf.name, err)
	}
	_, err = w.Write(zf.contents)
	if err != nil {
		return fmt.Errorf("writing %s to zip file: %w", zf.name, err)
	}
	return nil
}

func (a *analyzer) createStoreCommand(
	f, command string,
	args ...string,
) func() {
	return func() {
		cmd := exec.Command(command, args...) //nolint:gas // preexisting
		output, err := cmd.CombinedOutput()
		if err != nil {
			a.storeError(fmt.Errorf("getting data for %s: %w", f, err))
		}
		a.storeFile(f, output)
	}
}

func (a *analyzer) mtrCommands() []func() {
	// Determine what options the machine's mtr offers
	cmd := exec.Command("mtr", "--help")
	output, err := cmd.CombinedOutput()
	if err != nil {
		a.storeError(fmt.Errorf("determining mtr command: %s: %w", output, err))
		return []func(){}
	}

	// Select the display mode and file extension based on the machine's
	// mtr capabilities.
	var displayArgs []string
	var fileExt string
	switch {
	case bytes.Contains(output, []byte("--json")):
		displayArgs = []string{"--json"}
		fileExt = "json"
	case bytes.Contains(output, []byte("--report-wide")):
		displayArgs = []string{"--report-wide"}
		fileExt = "txt"
	default:
		displayArgs = []string{"--report", "--no-dns"}
		fileExt = "txt"
	}

	return []func(){
		a.createStoreCommand(host+"-mtr-ipv4."+fileExt, "mtr", append(displayArgs, "-4", host)...),
		a.createStoreCommand(host+"-mtr-ipv6."+fileExt, "mtr", append(displayArgs, "-6", host)...),
	}
}

func (a *analyzer) addIP() {
	resp, err := http.Get("http://" + host + "/app/update_getipaddr") //nolint:noctx // preexisting
	if err != nil {
		err = fmt.Errorf("getting IP address: %w", err)
		a.storeError(err)
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		_ = resp.Body.Close()
		err = fmt.Errorf("reading IP address body: %w", err)
		a.storeError(err)
		return
	}

	a.storeFile("ip-address.txt", body)
}

func (a *analyzer) addResolvConf() {
	contents, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		err = fmt.Errorf("reading resolv.conf: %w", err)
		a.storeError(err)
		return
	}
	a.storeFile("resolv.conf", contents)
}

func (a *analyzer) addErrors() error {
	a.errorsMutex.Lock()
	defer a.errorsMutex.Unlock()
	if len(a.errors) == 0 {
		return nil
	}
	buf := new(bytes.Buffer)
	for _, storedErr := range a.errors {
		_, err := fmt.Fprintf(buf, "%+v\n\n----------\n\n", storedErr)
		if err != nil {
			return fmt.Errorf("writing errors.txt buffer: %w", err)
		}
	}
	a.storeFile("errors.txt", buf.Bytes())
	return nil
}

func (a *analyzer) writeFiles() error {
	a.errorsMutex.Lock()
	defer a.errorsMutex.Unlock()
	for _, zf := range a.zipFiles {
		err := a.writeFile(zf)
		if err != nil {
			return err
		}
	}
	return nil
}
