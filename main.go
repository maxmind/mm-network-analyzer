// network-analyzer collects data about the machine it is running on and its
// network connection to help diagnose routing, DNS, and other issues to
// MaxMind servers.
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sync"

	"github.com/pkg/errors"
)

const (
	host        = "geoip.maxmind.com"
	zipFileName = "maxmind-network-analysis.zip"
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

	tasks := []func(){
		a.createStoreCommand(host+"-dig.txt", "dig", host),
		a.createStoreCommand("ip-addr.txt", "ip", "addr"),
		a.createStoreCommand("ip-route.txt", "ip", "route"),
		a.createStoreCommand(host+"-mtr-ipv4.json", "mtr", "-j", "-4", host),
		a.createStoreCommand(host+"-mtr-ipv6.json", "mtr", "-j", "-6", host),
		a.createStoreCommand(host+"-ping-ipv4.txt", "ping", "-4", "-c", "5", host),
		a.createStoreCommand(host+"-ping-ipv6.txt", "ping", "-6", "-c", "5", host),
		a.createStoreCommand(host+"-tracepath.txt", "tracepath", host),
		a.addIP,
		a.addResolvConf,
	}

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
	f, err := os.OpenFile(zipFileName, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return nil, errors.Wrap(err, "error opening "+zipFileName)
	}

	return &analyzer{
		zipWriter: zip.NewWriter(f),
		zipFile:   f,
	}, nil
}

func (a *analyzer) close() error {
	err := a.zipWriter.Close()
	if err != nil {
		return errors.Wrap(err, "error closing zip file writer")
	}
	err = a.zipFile.Close()
	if err != nil {
		return errors.Wrap(err, "error closing zip file")
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
	f, err := a.zipWriter.Create(zf.name)
	if err != nil {
		return errors.Wrap(err, "error creating "+zf.name+" in zip file")
	}
	_, err = f.Write(zf.contents)
	if err != nil {
		return errors.Wrap(err, "error writing "+zf.name+" to zip file")
	}
	return nil
}

func (a *analyzer) createStoreCommand(
	f, command string,
	args ...string,
) func() {
	return func() {
		cmd := exec.Command(command, args...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			a.storeError(errors.Wrapf(err, "error getting data for %s", f))
		}
		a.storeFile(f, output)
	}
}

func (a *analyzer) addIP() {
	resp, err := http.Get("http://" + host + "/app/update_getipaddr")
	if err != nil {
		err = errors.Wrap(err, "error getting IP address")
		a.storeError(err)
		return
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		err = errors.Wrap(err, "error reading IP address body")
		a.storeError(err)
		return
	}

	a.storeFile("ip-address.txt", body)
}

func (a *analyzer) addResolvConf() {
	contents, err := ioutil.ReadFile("/etc/resolv.conf")
	if err != nil {
		err = errors.Wrap(err, "error reading resolv.conf")
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
			return errors.Wrap(err, "error writing errors.txt buffer")
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
