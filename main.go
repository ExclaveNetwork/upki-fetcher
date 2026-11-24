/*
Copyright 2026 dyhkwong

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
)

const defaultBaseURL = "https://upki.rustls.dev/revocation/"

func defaultCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(dir, "dev.rustls.upki", "revocation")
	case "windows":
		return filepath.Join(dir, "rustls", "upki", "cache", "revocation")
	default:
		return filepath.Join(dir, "upki", "revocation")
	}
}

type manifest struct {
	GeneratedAt uint64         `json:"generated_at"`
	Comment     string         `json:"comment"`
	Files       []manifestFile `json:"files"`
	Filters     []manifestFile `json:"filters"`
}

type manifestFile struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Hash     string `json:"hash"`
}

type coverageEntry struct {
	logID [32]byte
	low   uint64
	high  uint64
}

type logEntry struct {
	filterIndex uint16
	low         uint64
	high        uint64
}

func main() {
	url := flag.String("url", defaultBaseURL, "mirror base URL")
	dir := flag.String("dir", defaultCacheDir(), "revocation cache directory")
	flag.Parse()
	if err := run(*url, *dir); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(baseURL, cacheDir string) error {
	if len(cacheDir) == 0 {
		return errors.New("invalid cache directory")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return err
	}
	client := &http.Client{}

	manifestURL := u.JoinPath("manifest.json").String()
	manifestBytes, err := fetch(client, manifestURL)
	if err != nil {
		return err
	}
	var manifest manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return err
	}
	if len(manifest.Files) == 0 && len(manifest.Filters) > 0 {
		manifest.Files = manifest.Filters
	}
	manifest.Filters = nil
	if manifest.GeneratedAt == 0 {
		return errors.New("invalid `generated_at` in manifest")
	}

	if len(manifest.Files) == 0 || len(manifest.Files) > 65535 {
		return errors.New("invalid filter amount for upkiidx1")
	}

	seen := make(map[string]bool, len(manifest.Files))
	for _, f := range manifest.Files {
		if seen[f.Filename] {
			return errors.New("duplicate filename in manifest: " + f.Filename)
		}
		seen[f.Filename] = true
		if _, err := decodeHash(f.Hash); err != nil {
			return err
		}
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}

	for _, f := range manifest.Files {
		dst := filepath.Join(cacheDir, f.Filename)
		want, err := decodeHash(f.Hash)
		if err != nil {
			return err
		}
		if existing, err := hashFile(dst); err == nil && bytes.Equal(existing, want) {
			continue
		}
		fileURL := u.JoinPath(f.Filename).String()
		data, err := fetch(client, fileURL)
		if err != nil {
			return err
		}
		if sum := sha256.Sum256(data); !bytes.Equal(sum[:], want) {
			return errors.New("checksum mismatch")
		}
		if err := writeFile(dst, data, 0o644); err != nil {
			return err
		}
	}

	index, err := buildIndex(cacheDir, manifest)
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(cacheDir, "index.bin"), index, 0o644); err != nil {
		return err
	}

	normalized, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	normalized = append(normalized, '\n')
	if err := writeFile(filepath.Join(cacheDir, "manifest.json"), normalized, 0o644); err != nil {
		return err
	}

	for _, ext := range []string{".filter", ".delta"} {
		matches, _ := filepath.Glob(filepath.Join(cacheDir, "*"+ext))
		for _, filename := range matches {
			if !seen[filepath.Base(filename)] {
				if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
	}
	return nil
}

func fetch(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json, application/octet-stream, */*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("invalid status code: " + strconv.Itoa(resp.StatusCode))
	}
	return io.ReadAll(resp.Body)
}

func decodeHash(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != sha256.Size {
		return nil, errors.New("invalid checksum size")
	}
	return b, nil
}

func hashFile(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, err = io.Copy(h, file)
	file.Close()
	if err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func buildIndex(cacheDir string, manifest manifest) ([]byte, error) {
	byLog := make(map[[32]byte][]logEntry)
	for i, f := range manifest.Files {
		data, err := os.ReadFile(filepath.Join(cacheDir, f.Filename))
		if err != nil {
			return nil, err
		}
		coverage, err := parseCoverage(data)
		if err != nil {
			return nil, err
		}
		for _, c := range coverage {
			byLog[c.logID] = append(byLog[c.logID], logEntry{
				filterIndex: uint16(i), low: c.low, high: c.high,
			})
		}
	}
	if uint64(len(byLog)) > uint64(^uint32(0)) {
		return nil, errors.New("too many CT log IDs")
	}

	logIDs := make([][32]byte, 0, len(byLog))
	for id := range byLog {
		logIDs = append(logIDs, id)
	}
	sort.Slice(logIDs, func(i, j int) bool {
		return bytes.Compare(logIDs[i][:], logIDs[j][:]) < 0
	})

	headerSize := 14 + len(manifest.Files)*32 + len(logIDs)*42
	var out bytes.Buffer
	out.Grow(headerSize + len(logIDs)*18)
	out.WriteString("upkiidx1")
	_ = binary.Write(&out, binary.BigEndian, uint16(len(manifest.Files)))
	_ = binary.Write(&out, binary.BigEndian, uint32(len(logIDs)))

	for _, f := range manifest.Files {
		slot := make([]byte, 32)
		copy(slot, []byte(f.Filename))
		out.Write(slot)
	}

	offset := uint64(headerSize)
	for _, id := range logIDs {
		entries := byLog[id]
		if len(entries) > 65535 {
			return nil, errors.New("too many coverage entries")
		}
		out.Write(id[:])
		_ = binary.Write(&out, binary.BigEndian, offset)
		_ = binary.Write(&out, binary.BigEndian, uint16(len(entries)))
		offset += uint64(len(entries)) * 18
	}
	for _, id := range logIDs {
		for _, e := range byLog[id] {
			_ = binary.Write(&out, binary.BigEndian, e.filterIndex)
			_ = binary.Write(&out, binary.BigEndian, e.low)
			_ = binary.Write(&out, binary.BigEndian, e.high)
		}
	}
	return out.Bytes(), nil
}

func parseCoverage(data []byte) ([]coverageEntry, error) {
	if len(data) < 4 {
		return nil, errors.New("truncated filter header/coverage")
	}
	if data[0] != 4 {
		return nil, errors.New("unsupported clubcard version")
	}
	if data[1] != 0 {
		return nil, errors.New("reserved byte is non-zero")
	}
	count := int(binary.BigEndian.Uint16(data[2:4]))
	if need := 4 + count*48; need > len(data) {
		return nil, errors.New("coverage truncated")
	}
	out := make([]coverageEntry, 0, count)
	seen := make(map[[32]byte]bool, count)
	off := 4
	for i := 0; i < count; i++ {
		var e coverageEntry
		copy(e.logID[:], data[off:off+32])
		e.low = binary.BigEndian.Uint64(data[off+32 : off+40])
		e.high = binary.BigEndian.Uint64(data[off+40 : off+48])
		if seen[e.logID] {
			return nil, errors.New("duplicate log ID in coverage entry")
		}
		if e.low > e.high {
			return nil, errors.New("invalid timestamp interval in coverage entry")
		}
		seen[e.logID] = true
		out = append(out, e)
		off += 48
	}
	return out, nil
}

func writeFile(filename string, data []byte, mode os.FileMode) error {
	tempFile, err := os.CreateTemp(filepath.Dir(filename), ".upki-fetch-*")
	if err != nil {
		return err
	}
	defer os.Remove(tempFile.Name())
	if err := tempFile.Chmod(mode); err != nil {
		tempFile.Close()
		return err
	}
	if _, err := tempFile.Write(data); err != nil {
		tempFile.Close()
		return err
	}
	if err := tempFile.Sync(); err != nil {
		tempFile.Close()
		return err
	}
	tempFile.Close()
	return os.Rename(tempFile.Name(), filename)
}
