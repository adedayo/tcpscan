package portscan

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dgraph-io/badger"
)

var (
	dayFormat           = "2006-01-02"
	baseScanDBDirectory = filepath.FromSlash("data/tcpscan/scan")
	psrCache            = make(map[string]PersistedScanRequest)
	lock                = sync.RWMutex{}
	scanCacheLock       = sync.RWMutex{}
)

//ListScans returns the ScanID list of  persisted scans
func ListScans(rewindDays int, completed bool) (result []ScanRequest) {
	if rewindDays < 0 {
		log.Print("The number of days in the past must be non-negative.")
		return
	}
	dirs, err := ioutil.ReadDir(baseScanDBDirectory)
	if err != nil {
		log.Print(err)
		return
	}

	allowedDates := make(map[string]bool)
	today := time.Now()
	for d := rewindDays; d >= 0; d-- {
		allowedDates[fmt.Sprintf("%s", today.AddDate(0, 0, -1*d).Format(dayFormat))] = true
	}

	matchedDirs := []string{}
	for _, d := range dirs {
		dirName := d.Name()
		if _, present := allowedDates[dirName]; present {
			matchedDirs = append(matchedDirs, dirName)
		}
	}

	for _, d := range matchedDirs {
		dirs, err := ioutil.ReadDir(filepath.Join(baseScanDBDirectory, d))
		if err != nil {
			log.Print(err)
			return
		}

		for _, sID := range dirs {
			scanID := sID.Name()
			//LoadScanRequest retrieves persisted scan request from folder following a layout pattern
			if psr, err := LoadScanRequest(d, scanID); err == nil && (len(psr.Hosts) == psr.Progress) == completed {
				result = append(result, psr.Request)
			}
		}
	}
	return
}

//PersistScans persists the result of scans per server
func PersistScans(psr PersistedScanRequest, server string, scans []PortACK) {
	dbDir := filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID)
	opts := badger.DefaultOptions(dbDir)
	opts.NumVersionsToKeep = 0
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer db.Close()

	db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(server), marshallPortAcks(scans))
	})
}

//LoadScanRequest retrieves persisted scan request from folder following a layout pattern
func LoadScanRequest(dir, scanID string) (psr PersistedScanRequest, e error) {
	lock.Lock()
	if psr, ok := psrCache[fmt.Sprintf("%s:%s", dir, scanID)]; ok {
		lock.Unlock()
		return psr, nil
	}
	lock.Unlock()
	dbDir := filepath.Join(baseScanDBDirectory, dir, scanID, "request")
	opts := badger.DefaultOptions(dbDir)
	opts.ReadOnly = true
	db, err := badger.Open(opts)
	if err != nil {
		return psr, err
	}
	defer db.Close()
	data := []byte{}
	outErr := db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(scanID))
		if err != nil {
			return err
		}

		data, err = item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return nil
	})
	if outErr != nil {
		return psr, outErr
	}
	psr, e = UnmasharlPersistedScanRequest(data)
	if e == nil && len(psr.Hosts) == psr.Progress {
		lock.Lock()
		psrCache[fmt.Sprintf("%s:%s", dir, scanID)] = psr
		lock.Unlock()
	}
	return psr, e
}

//Marshall scan request
func (psr PersistedScanRequest) Marshall() []byte {
	result := bytes.Buffer{}
	gob.Register(PersistedScanRequest{})
	err := gob.NewEncoder(&result).Encode(&psr)
	if err != nil {
		log.Print(err)
	}
	return result.Bytes()
}

//UnmasharlPersistedScanRequest builds PersistedScanRequest from bytes
func UnmasharlPersistedScanRequest(data []byte) (PersistedScanRequest, error) {

	psr := PersistedScanRequest{}
	gob.Register(psr)
	buf := bytes.NewBuffer(data)
	err := gob.NewDecoder(buf).Decode(&psr)
	if err != nil {
		return psr, err
	}
	return psr, nil
}

func marshallPortAcks(s []PortACK) []byte {
	result := bytes.Buffer{}
	gob.Register([]PortACK{})
	err := gob.NewEncoder(&result).Encode(&s)
	if err != nil {
		log.Print(err)
	}
	return result.Bytes()
}

//PersistScanRequest persists scan request
func PersistScanRequest(psr PersistedScanRequest) {
	dbDir := filepath.Join(baseScanDBDirectory, psr.Request.Day, psr.Request.ScanID, "request")
	opts := badger.DefaultOptions(dbDir)
	opts.NumVersionsToKeep = 0
	db, err := badger.Open(opts)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer db.Close()

	db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(psr.Request.ScanID), psr.Marshall())
	})
}

//CompactDB reclaims space by pruning the database
func CompactDB(dayPath, scanID string) {
	//compact the scan requests
	dbDir := filepath.Join(baseScanDBDirectory, dayPath, scanID, "request")
	opts := badger.DefaultOptions(dbDir)
	opts.NumVersionsToKeep = 0
	db, err := badger.Open(opts)
	if err != nil {
		println(err.Error())
		log.Fatal(err)
		return
	}
	lsmx, vlogx := db.Size()
	for db.RunValueLogGC(.8) == nil {
		lsmy, vlogy := db.Size()
		println("Compacted DB", opts.Dir)
		fmt.Printf("Before LSM: %d, VLOG: %d, After LSM: %d, VLOG: %d\n", lsmx, vlogx, lsmy, vlogy)
		lsmx, vlogx = lsmy, vlogy
	}
	db.Close()
}

//GetNextScanID returns the next unique scan ID
func GetNextScanID() string {
	prefix := filepath.Join(baseScanDBDirectory, time.Now().Format(dayFormat))
	if _, err := os.Stat(prefix); os.IsNotExist(err) {
		if err2 := os.MkdirAll(prefix, 0755); err2 != nil {
			log.Fatal("Could not create the path ", prefix)
		}
	}
	dir, err := ioutil.TempDir(prefix, "")
	if err != nil {
		log.Fatal(err)
		return ""
	}
	return strings.Replace(strings.TrimPrefix(dir, prefix), string(os.PathSeparator), "", -1)
}
