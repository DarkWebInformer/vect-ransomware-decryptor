package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	nonceSize = 12
	tagSize   = 16
	overhead  = nonceSize + tagSize
	blockSize = 0x100000
	encExt    = ".vect1"
	hexRows   = 4
)

func hexdump(label string, data []byte) {
	n := hexRows * 16
	if len(data) < n {
		n = len(data)
	}
	chunk := data[:n]

	fmt.Printf("  %-6s  offset   00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  │ ASCII\n", label)
	fmt.Printf("  ------  ------   -----------------------------------------------  │ ----------------\n")

	for i := 0; i < len(chunk); i += 16 {
		j := i + 16
		if j > len(chunk) {
			j = len(chunk)
		}
		row := chunk[i:j]

		fmt.Printf("          %06x   ", i)
		for k := 0; k < 16; k++ {
			if k == 8 {
				fmt.Print(" ")
			}
			if k < len(row) {
				fmt.Printf("%02x ", row[k])
			} else {
				fmt.Print("   ")
			}
		}

		fmt.Print(" │ ")
		for _, b := range row {
			if b < 128 && unicode.IsPrint(rune(b)) {
				fmt.Printf("%c", b)
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println()
	}

	if len(data) > hexRows*16 {
		fmt.Printf("          ...      (%d bytes total)\n", len(data))
	}
	fmt.Println()
}

func decryptBlock(key, nonce, ctAndTag []byte) ([]byte, bool) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, false
	}
	out, err := aead.Open(nil, nonce, ctAndTag, nil)
	if err != nil {
		return nil, false
	}
	return out, true
}

func readTestBlock(path string) (nonce []byte, ctAndTag []byte, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	buf := make([]byte, nonceSize+blockSize+tagSize)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil, nil, err
	}
	buf = buf[:n]

	if len(buf) < overhead+1 {
		return nil, nil, fmt.Errorf("file too small to use as oracle")
	}
	return buf[:nonceSize], buf[nonceSize:], nil
}

func extractKey(binaryPath, samplePath string) ([]byte, error) {
	nonce, ctAndTag, err := readTestBlock(samplePath)
	if err != nil {
		return nil, fmt.Errorf("reading sample: %w", err)
	}

	raw, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("reading binary: %w", err)
	}

	window := len(raw) - 32 + 1
	if window <= 0 {
		return nil, fmt.Errorf("binary too small")
	}

	fmt.Printf("[*] Scanning %d bytes (%d candidates)...\n", len(raw), window)

	for at := 0; at < window; at++ {
		k := raw[at : at+32]
		if _, ok := decryptBlock(k, nonce, ctAndTag); ok {
			fmt.Printf("[+] Key found at binary offset 0x%08x\n", at)
			out := make([]byte, 32)
			copy(out, k)
			return out, nil
		}
	}
	return nil, fmt.Errorf("key not found in binary")
}

func decryptFile(key []byte, encPath string, backup, dump bool) bool {
	if !strings.HasSuffix(encPath, encExt) {
		return false
	}
	decPath := strings.TrimSuffix(encPath, encExt)

	st, err := os.Stat(encPath)
	if err != nil {
		fmt.Printf("[-] Stat failed: %s\n", encPath)
		return false
	}
	size := st.Size()

	if size < overhead {
		fmt.Printf("[-] Too small: %s\n", encPath)
		return false
	}

	body, err := os.ReadFile(encPath)
	if err != nil {
		fmt.Printf("[-] Read failed: %s\n", encPath)
		return false
	}

	if backup {
		_ = os.WriteFile(encPath+".bak", body, 0644)
	}

	fmt.Printf("\n[>] %s\n", filepath.Base(encPath))

	if dump {
		fmt.Printf("  Nonce: %s\n\n", hex.EncodeToString(body[:nonceSize]))
		hexdump("BEFORE", body[nonceSize:])
	}

	var plain []byte

	if size <= blockSize+overhead {
		p, ok := decryptBlock(key, body[:nonceSize], body[nonceSize:])
		if !ok {
			fmt.Printf("[-] Auth failure (wrong key?): %s\n", filepath.Base(encPath))
			return false
		}
		plain = p
	} else {
		endFirst := int64(blockSize + overhead)
		head, ok := decryptBlock(key, body[:nonceSize], body[nonceSize:endFirst])
		if !ok {
			fmt.Printf("[-] Auth failure (wrong key?): %s\n", filepath.Base(encPath))
			return false
		}

		tailOff := size - overhead
		mid := body[endFirst:tailOff]
		tail := body[tailOff:]
		z := make([]byte, overhead)

		plain = head
		plain = append(plain, z...)
		plain = append(plain, mid...)
		plain = append(plain, tail...)

		wantLen := size - overhead
		if int64(len(plain)) > wantLen {
			plain = plain[:wantLen]
		}
	}

	if dump {
		hexdump("AFTER", plain)
	}

	if err := os.WriteFile(encPath, plain, 0644); err != nil {
		fmt.Printf("[-] Write failed: %s\n", encPath)
		return false
	}

	if err := os.Rename(encPath, decPath); err != nil {
		fmt.Printf("[-] Rename failed (%v): %s\n", err, encPath)
		return false
	}

	fmt.Printf("[+] %s  ->  %s  (%d bytes)\n",
		filepath.Base(encPath), filepath.Base(decPath), len(plain))
	return true
}

func decryptDirectory(key []byte, dir string, backup, dump bool) (ok, failed int) {
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, encExt) {
			if decryptFile(key, path, backup, dump) {
				ok++
			} else {
				failed++
			}
		}
		return nil
	})
	return ok, failed
}

func usage() {
	fmt.Println(`Usage:
  vect1_decryptor extract-key -binary locker.exe -sample file.vect1 [-out key.txt]
  vect1_decryptor decrypt      -target <path>    -key <hex64>        [-backup] [-hexdump]
  vect1_decryptor auto         -binary locker.exe -target <dir>      [-backup] [-hexdump]`)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "extract-key":
		fl := flag.NewFlagSet("extract-key", flag.ExitOnError)
		binary := fl.String("binary", "", "")
		sample := fl.String("sample", "", "")
		outPath := fl.String("out", "", "")
		fl.Parse(args)

		if *binary == "" || *sample == "" {
			fmt.Println("[-] -binary and -sample are required.")
			fl.Usage()
			os.Exit(1)
		}

		key, err := extractKey(*binary, *sample)
		if err != nil {
			fmt.Printf("[-] %v\n", err)
			os.Exit(1)
		}
		keyHex := hex.EncodeToString(key)
		fmt.Printf("[+] Key (hex): %s\n", keyHex)
		if *outPath != "" {
			err := os.WriteFile(*outPath, []byte(keyHex), 0600)
			if err != nil {
				fmt.Printf("[-] Could not save key: %v\n", err)
			} else {
				fmt.Printf("[+] Saved to %s\n", *outPath)
			}
		}

	case "decrypt":
		fl := flag.NewFlagSet("decrypt", flag.ExitOnError)
		path := fl.String("target", "", "")
		keyHex := fl.String("key", "", "")
		backup := fl.Bool("backup", false, "")
		dump := fl.Bool("hexdump", false, "")
		fl.Parse(args)

		if *path == "" || *keyHex == "" {
			fmt.Println("[-] -target and -key are required.")
			fl.Usage()
			os.Exit(1)
		}
		key, err := hex.DecodeString(*keyHex)
		if err != nil || len(key) != 32 {
			fmt.Println("[-] Key must be exactly 64 hex characters (32 bytes).")
			os.Exit(1)
		}

		info, err := os.Stat(*path)
		if err != nil {
			fmt.Printf("[-] Target not found: %s\n", *path)
			os.Exit(1)
		}
		if info.IsDir() {
			ok, bad := decryptDirectory(key, *path, *backup, *dump)
			fmt.Printf("\n[*] Done: %d decrypted, %d failed\n", ok, bad)
		} else {
			decryptFile(key, *path, *backup, *dump)
		}

	case "auto":
		fl := flag.NewFlagSet("auto", flag.ExitOnError)
		binary := fl.String("binary", "", "")
		target := fl.String("target", "", "")
		backup := fl.Bool("backup", false, "")
		dump := fl.Bool("hexdump", false, "")
		fl.Parse(args)

		if *binary == "" || *target == "" {
			fmt.Println("[-] -binary and -target are required.")
			fl.Usage()
			os.Exit(1)
		}

		var sample string
		_ = filepath.WalkDir(*target, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || sample != "" {
				return nil
			}
			if strings.HasSuffix(p, encExt) {
				sample = p
			}
			return nil
		})
		if sample == "" {
			fmt.Printf("[-] No %s files found in %s\n", encExt, *target)
			os.Exit(1)
		}
		fmt.Printf("[*] Using %s as decryption oracle\n", filepath.Base(sample))

		key, err := extractKey(*binary, sample)
		if err != nil {
			fmt.Printf("[-] %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] Key: %s\n", hex.EncodeToString(key))

		ok, bad := decryptDirectory(key, *target, *backup, *dump)
		fmt.Printf("\n[*] Done: %d decrypted, %d failed\n", ok, bad)

	default:
		fmt.Printf("[-] Unknown command: %s\n", cmd)
		usage()
	}
}
