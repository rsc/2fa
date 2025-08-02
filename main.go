package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/pbkdf2"
)

type KeyName string

// validate checks if the KeyName is valid.
// Returns an error if the name contains spaces or is empty.
func (kn KeyName) validate() error {
	if len(kn) == 0 {
		return fmt.Errorf("key name cannot be empty")
	}
	if strings.IndexFunc(string(kn), unicode.IsSpace) >= 0 {
		return fmt.Errorf("key name must not contain spaces")
	}
	return nil
}

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)

	app := &cli.Command{
		Name:  "2fa",
		Usage: "Two-factor authentication agent",
		Commands: []*cli.Command{
			{
				Name:  "add",
				Usage: "Add a new key to the keychain",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "hotp",
						Usage: "Add key as HOTP (counter-based) key",
					},
					&cli.BoolFlag{
						Name:  "7",
						Usage: "Generate 7-digit code",
					},
					&cli.BoolFlag{
						Name:  "8",
						Usage: "Generate 8-digit code",
					},
				},
				Action: func(_ context.Context, c *cli.Command) error {
					if c.NArg() != 1 {
						return fmt.Errorf("usage: 2fa add [-7] [-8] [-hotp] keyname")
					}
					name := KeyName(c.Args().First())
					configDir, err := os.UserConfigDir()
					if err != nil {
						return fmt.Errorf("getting user config dir: %v", err)
					}
					keychainFile := filepath.Join(configDir, "2fa", "2fa")
					k := readKeychain(keychainFile)
					k.add(name, c.Bool("hotp"), c.Bool("7"), c.Bool("8"))
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List all keys in the keychain",
				Action: func(_ context.Context, c *cli.Command) error {
					if c.NArg() != 0 {
						return fmt.Errorf("usage: 2fa list")
					}
					configDir, err := os.UserConfigDir()
					if err != nil {
						return fmt.Errorf("getting user config dir: %v", err)
					}
					keychainFile := filepath.Join(configDir, "2fa", "2fa")
					k := readKeychain(keychainFile)
					k.list()
					return nil
				},
			},
			{
				Name:  "show",
				Usage: "Show a two-factor authentication code for a key",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "clip",
						Usage: "Copy code to the clipboard",
					},
				},
				Action: func(_ context.Context, c *cli.Command) error {
					if c.NArg() != 1 {
						return fmt.Errorf("usage: 2fa show [--clip] keyname")
					}
					name := KeyName(c.Args().First())
					configDir, err := os.UserConfigDir()
					if err != nil {
						return fmt.Errorf("getting user config dir: %v", err)
					}
					keychainFile := filepath.Join(configDir, "2fa", "2fa")
					k := readKeychain(keychainFile)
					k.show(name, c.Bool("clip"))
					return nil
				},
			},
			{
				Name:  "import",
				Usage: "Import keys from a URI-list file",
				Action: func(_ context.Context, c *cli.Command) error {
					if c.NArg() != 1 {
						return fmt.Errorf("usage: 2fa import uri_list_file")
					}
					configDir, err := os.UserConfigDir()
					if err != nil {
						return fmt.Errorf("getting user config dir: %v", err)
					}
					keychainFile := filepath.Join(configDir, "2fa", "2fa")
					k := readKeychain(keychainFile)
					k.importURIList(c.Args().First())
					return nil
				},
			},
			{
				Name:  "export",
				Usage: "Export keys to a URI-list file or stdout",
				Action: func(_ context.Context, c *cli.Command) error {
					if c.NArg() > 1 {
						return fmt.Errorf("usage: 2fa export [uri_list_file | -]")
					}
					configDir, err := os.UserConfigDir()
					if err != nil {
						return fmt.Errorf("getting user config dir: %v", err)
					}
					keychainFile := filepath.Join(configDir, "2fa", "2fa")
					k := readKeychain(keychainFile)
					if c.NArg() == 0 || c.Args().First() == "-" {
						k.exportURIList(os.Stdout)
					} else {
						f, err := os.OpenFile(c.Args().First(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
						if err != nil {
							return fmt.Errorf("opening export file: %v", err)
						}
						defer f.Close()
						k.exportURIList(f)
					}
					return nil
				},
			},
		},
		Action: func(_ context.Context, c *cli.Command) error {
			if c.NArg() > 0 {
				return fmt.Errorf("usage: 2fa [--clip] [keyname]")
			}
			configDir, err := os.UserConfigDir()
			if err != nil {
				return fmt.Errorf("getting user config dir: %v", err)
			}
			keychainFile := filepath.Join(configDir, "2fa", "2fa")
			k := readKeychain(keychainFile)
			k.showAll()
			return nil
		},
	}

	app.Authors = []any{
		&mail.Address{Name: "xplshn", Address: "anto@xplshn.com.ar"},
		&mail.Address{Name: "rsc", Address: "rsc@swtch.com"},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

type Keychain struct {
	file string
	data []byte
	keys map[KeyName]Key
}

type Key struct {
	uri    *url.URL // Store the full URI
	raw    []byte   // Decoded secret
	digits int      // Number of digits
	offset int      // Offset of counter in data (for HOTP)
}

const counterLen = 20

func getEncryptionKey() ([]byte, error) {
	uuid, err := os.ReadFile("/sys/class/dmi/id/product_uuid")
	if err != nil {
		return nil, fmt.Errorf("cannot read machine UUID: %v", err)
	}
	return pbkdf2.Key(uuid, []byte("2fa-salt"), 100000, 32, sha256.New), nil
}

func encrypt(data []byte) ([]byte, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padData := make([]byte, len(data)+padding)
	copy(padData, data)
	for i := len(data); i < len(padData); i++ {
		padData[i] = byte(padding)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(padData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padData)
	return append(iv, ciphertext...), nil
}

func decrypt(data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("encrypted data too short")
	}
	key, err := getEncryptionKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)
	padding := int(plaintext[len(plaintext)-1])
	if padding > len(plaintext) || padding > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(plaintext) - padding; i < len(plaintext); i++ {
		if plaintext[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

func readKeychain(file string) *Keychain {
	c := &Keychain{
		file: file,
		keys: make(map[KeyName]Key),
	}
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}
	c.data, err = decrypt(data)
	if err != nil {
		log.Fatalf("decrypting keychain: %v", err)
	}

	lines := bytes.SplitAfter(c.data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		line = bytes.TrimSuffix(line, []byte("\n"))
		if len(line) == 0 {
			offset += len(line) + 1
			continue
		}
		if !bytes.HasPrefix(line, []byte("otpauth://")) {
			log.Printf("%s:%d: invalid URI format", c.file, lineno)
			offset += len(line) + 1
			continue
		}
		u, err := url.Parse(string(line))
		if err != nil {
			log.Printf("%s:%d: parsing URI: %v", c.file, lineno, err)
			offset += len(line) + 1
			continue
		}
		name := strings.TrimPrefix(u.Path, "/")
		keyName := KeyName(name)
		if err := keyName.validate(); err != nil {
			log.Printf("%s:%d: %v", c.file, lineno, err)
			offset += len(line) + 1
			continue
		}
		secret := u.Query().Get("secret")
		if secret == "" {
			log.Printf("%s:%d: no secret in URI", c.file, lineno)
			offset += len(line) + 1
			continue
		}
		digits := 6
		if d := u.Query().Get("digits"); d != "" {
			n, err := strconv.Atoi(d)
			if err == nil && (n == 6 || n == 7 || n == 8) {
				digits = n
			}
		}
		var k Key
		k.uri = u
		k.digits = digits
		k.raw, err = decodeKey(secret)
		if err != nil {
			log.Printf("%s:%d: invalid secret: %v", c.file, lineno, err)
			offset += len(line) + 1
			continue
		}
		if u.Host == "hotp" {
			counter := u.Query().Get("counter")
			if counter != "" {
				_, err := strconv.ParseUint(counter, 10, 64)
				if err != nil {
					log.Printf("%s:%d: invalid counter: %v", c.file, lineno, err)
					offset += len(line) + 1
					continue
				}
				k.offset = offset + len(line) - len(counter)
			}
		}
		c.keys[keyName] = k
		offset += len(line) + 1
	}
	return c
}

func (c *Keychain) list() {
	var names []string
	for name := range c.keys {
		names = append(names, string(name))
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (c *Keychain) add(name KeyName, hotp, flag7, flag8 bool) {
	if err := name.validate(); err != nil {
		log.Fatalf("invalid key name: %v", err)
	}
	size := 6
	if flag7 {
		size = 7
		if flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if flag8 {
		size = 8
	}

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7)
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	query := url.Values{}
	query.Set("secret", text)
	query.Set("digits", strconv.Itoa(size))
	uriType := "totp"
	if hotp {
		uriType = "hotp"
		query.Set("counter", strings.Repeat("0", counterLen))
	}
	uri := &url.URL{
		Scheme:   "otpauth",
		Host:     uriType,
		Path:     "/" + url.QueryEscape(string(name)),
		RawQuery: query.Encode(),
	}
	line := uri.String() + "\n"

	c.data = append(c.data, []byte(line)...)

	if err := os.MkdirAll(filepath.Dir(c.file), 0700); err != nil {
		log.Fatalf("creating config directory: %v", err)
	}

	encrypted, err := encrypt(c.data)
	if err != nil {
		log.Fatalf("encrypting keychain: %v", err)
	}
	if err := os.WriteFile(c.file, encrypted, 0600); err != nil {
		log.Fatalf("writing keychain: %v", err)
	}
}

func (c *Keychain) importURIList(file string) {
	data, err := os.ReadFile(file)
	if err != nil {
		log.Fatalf("reading URI list: %v", err)
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var newData []byte
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "otpauth://") {
			log.Printf("skipping non-URI line: %s", line)
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			log.Printf("parsing URI: %v", err)
			continue
		}
		name := strings.TrimPrefix(u.Path, "/")
		keyName := KeyName(name)
		if err := keyName.validate(); err != nil {
			log.Printf("invalid key name in URI: %v", err)
			continue
		}
		secret := u.Query().Get("secret")
		if secret == "" {
			log.Printf("no secret in URI: %s", line)
			continue
		}
		if _, err := decodeKey(secret); err != nil {
			log.Printf("invalid secret in URI: %s", line)
			continue
		}
		newData = append(newData, []byte(line+"\n")...)
	}
	if err := scanner.Err(); err != nil {
		log.Fatalf("reading URI list: %v", err)
	}
	c.data = append(c.data, newData...)
	if err := os.MkdirAll(filepath.Dir(c.file), 0700); err != nil {
		log.Fatalf("creating config directory: %v", err)
	}
	encrypted, err := encrypt(c.data)
	if err != nil {
		log.Fatalf("encrypting keychain: %v", err)
	}
	if err := os.WriteFile(c.file, encrypted, 0600); err != nil {
		log.Fatalf("writing keychain: %v", err)
	}
}

func (c *Keychain) exportURIList(w io.Writer) {
	var uriList []string
	for _, key := range c.keys {
		uriList = append(uriList, key.uri.String())
	}
	if len(uriList) == 0 {
		return
	}
	sort.Strings(uriList)
	_, err := io.WriteString(w, strings.Join(uriList, "\n")+"\n")
	if err != nil {
		log.Fatalf("writing URI list: %v", err)
	}
}

func (c *Keychain) code(name KeyName) string {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	if k.uri.Host == "hotp" {
		n, err := strconv.ParseUint(k.uri.Query().Get("counter"), 10, 64)
		if err != nil {
			log.Fatalf("malformed key counter for %q: %v", name, err)
		}
		n++
		code = hotp(k.raw, n, k.digits)
		query := k.uri.Query()
		query.Set("counter", fmt.Sprintf("%0*d", counterLen, n))
		k.uri.RawQuery = query.Encode()
		// Update URI in memory and file
		newURI := k.uri.String() + "\n"
		start := k.offset
		for start > 0 && c.data[start-1] != '\n' {
			start--
		}
		end := k.offset
		for end < len(c.data) && c.data[end] != '\n' {
			end++
		}
		if end < len(c.data) {
			end++ // Include newline
		}
		c.data = append(c.data[:start], append([]byte(newURI), c.data[end:]...)...)
		encrypted, err := encrypt(c.data)
		if err != nil {
			log.Fatalf("encrypting keychain: %v", err)
		}
		if err := os.WriteFile(c.file, encrypted, 0600); err != nil {
			log.Fatalf("writing keychain: %v", err)
		}
	} else {
		code = totp(k.raw, time.Now(), k.digits)
	}
	return fmt.Sprintf("%0*d", k.digits, code)
}

func (c *Keychain) show(name KeyName, clip bool) {
	if err := name.validate(); err != nil {
		log.Fatalf("invalid key name: %v", err)
	}
	code := c.code(name)
	if clip {
		clipboard.WriteAll(code)
	}
	fmt.Printf("%s\n", code)
}

func (c *Keychain) showAll() {
	var names []KeyName
	max := 0
	for name, k := range c.keys {
		names = append(names, name)
		if max < k.digits {
			max = k.digits
		}
	}
	sort.Slice(names, func(i, j int) bool { return names[i] < names[j] })
	for _, name := range names {
		k := c.keys[name]
		code := strings.Repeat("-", k.digits)
		if k.uri.Host == "totp" {
			code = c.code(name)
		}
		fmt.Printf("%-*s\t%s\n", max, code, name)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}


