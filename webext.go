package webext

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	rfs "io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/AspieSoft/go-regex-re2/v2"
	"github.com/AspieSoft/goutil/fs/v3"
	"github.com/AspieSoft/goutil/v7"
	"github.com/gofiber/fiber/v2"
)

// PWD is initialized to the parent working directory of your app
var PWD string

// IsRoot returns true if the EUID is 0
//
// (i.e. if you ran your app with sudo)
var IsRoot bool = os.Geteuid() == 0

var hasFailedSSL bool

func init(){
	var err error
	PWD, err = os.Getwd()
	if err != nil {
		panic(err)
	}
}


// VerifyOrigin can be added to `app.Use` to enforce that all connections
// are coming through a specified domain and proxy ip
//
// @origin: list of valid domains
//
// @proxy: list of valid ip proxies
//
// @handleErr: optional, allows you to define a function for handling invalid origins, instead of returning the default http error
func VerifyOrigin(origin []string, proxy []string, handleErr ...func(c *fiber.Ctx, err error) error) func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		hostname := string(regex.Comp(`:[0-9]+$`).RepStrLit([]byte(goutil.Clean.Str(c.Hostname())), []byte{}))
		ip := goutil.Clean.Str(c.IP())

		validOrigin := false
		for _, origin := range origin {
			if origin == hostname {
				validOrigin = true
				break
			}
		}

		if !validOrigin {
			if len(handleErr) != 0 {
				return handleErr[0](c, errors.New("Origin Not Allowed: "+hostname))
			}
			c.SendStatus(403)
			return c.SendString("Origin Not Allowed: "+hostname)
		}

		validProxy := false
		for _, proxy := range proxy {
			if proxy == ip {
				validProxy = true
				break
			}
		}

		if !validProxy || !c.IsProxyTrusted() {
			if len(handleErr) != 0 {
				return handleErr[0](c, errors.New("IP Proxy Not Allowed: "+ip))
			}
			c.SendStatus(403)
			return c.SendString("IP Proxy Not Allowed: "+ip)
		}

		return c.Next()
	}
}

// RedirectSSL can be added to `app.Use` to auto redirect http to https
//
// @httpPort: 80, @sslPort: 443
func RedirectSSL(httpPort, sslPort uint16) func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		if c.Secure() || hasFailedSSL {
			return c.Next()
		}

		var hostPort uint16
		if port, err := strconv.Atoi(string(regex.Comp(`^.*:([0-9]+)$`).RepStr([]byte(goutil.Clean.Str(c.Hostname())), []byte("$1")))); err == nil {
			hostPort = uint16(port)
		}

		if hostPort != sslPort && hostPort != 443 && c.Port() != strconv.Itoa(int(sslPort)) && c.Port() != "443" {
			hostname := string(regex.Comp(`:[0-9]+$`).RepStrLit([]byte(goutil.Clean.Str(c.Hostname())), []byte{}))

			if hostPort == httpPort || c.Port() == strconv.Itoa(int(httpPort)) {
				return c.Redirect("https://"+hostname+":"+strconv.Itoa(int(sslPort))+goutil.Clean.Str(c.OriginalURL()), 301)
			}

			return c.Redirect("https://"+hostname+goutil.Clean.Str(c.OriginalURL()), 301)
		}

		return c.Next()
	}
}

// ListenAutoTLS will automatically generate a self signed tls certificate
// if needed and listen to both http and https ports
//
// @httpPort: 80, @sslPort: 443
//
// @certPath: file path to store ssl certificates to (this will generate a my/path.crt and my/path.key file)
//
// @proxy: optional, if only one proxy is specified, the app will only listen to that ip address
func ListenAutoTLS(app *fiber.App, httpPort, sslPort uint16, certPath string, proxy ...[]string) error {
	certPath = string(regex.Comp(`\.(crt|key)$`).RepStrLit([]byte(certPath), []byte{}))

	if sslPort != 0 && certPath != "" {
		port := ":"+strconv.Itoa(int(sslPort))
		if len(proxy) == 1 && len(proxy[0]) == 1 {
			port = proxy[0][0] + port
		}

		// generate ssl cert if needed
		os.MkdirAll(filepath.Dir(certPath), TryPerm(0644, 0755))
		err := GenRsaKeyIfNeeded(certPath+".crt", certPath+".key")
		if err != nil {
			return err
		}

		// auto renew ssl cert if expired
		NewCron(24 * time.Hour, func() bool {
			err := GenRsaKeyIfNeeded(certPath+".crt", certPath+".key")
			if err != nil {
				fmt.Println(err)
				return false
			}
			return true
		})

		go func(){
			err := app.ListenTLS(port, certPath+".crt", certPath+".key")
			if err != nil {
				hasFailedSSL = true
			}
		}()
	}
	
	port := ":"+strconv.Itoa(int(httpPort))
	if len(proxy) == 1 && len(proxy[0]) == 1 {
		port = proxy[0][0] + port
	}

	return app.Listen(port)
}


var failedPermList []rfs.FileMode = []rfs.FileMode{}

// TryPerm attempts to set a directory permission to @perm only if it can access that directory
//
// if it fails due to permission restrictions, and if IsRoot returns false,
// it will instead return @nonrootPerm as a fallback
func TryPerm(perm rfs.FileMode, nonrootPerm rfs.FileMode) rfs.FileMode {
	if IsRoot {
		return perm
	}

	if goutil.Contains(failedPermList, perm) {
		return nonrootPerm
	}

	if err := os.Mkdir("test.tmp", perm); err != nil {
		os.RemoveAll("test.tmp")
		failedPermList = append(failedPermList, perm)
		return nonrootPerm
	}
	if err := os.WriteFile("test.tmp/test.tmp", []byte{}, perm); err != nil {
		os.RemoveAll("test.tmp")
		failedPermList = append(failedPermList, perm)
		return nonrootPerm
	}
	os.RemoveAll("test.tmp")

	return perm
}

// GenRsaKeyIfNeeded auto detects if the certificates generated by
// the GenRsaKey method are either
//  - not synchronized by date modified
//  - are possibly expired (assuming a 1 year renewal)
// If it detects this is true, it will automatically regenerate a new certificate
func GenRsaKeyIfNeeded(crtPath string, keyPath string) error {
	crtStat, crtErr := os.Stat(crtPath)
	keyStat, keyErr := os.Stat(keyPath)

	if crtErr != nil || keyErr != nil {
		err := GenRsaKey(crtPath, keyPath)
		if err != nil {
			return err
		}
		return nil
	}

	crtTime := crtStat.ModTime()
	keyTime := keyStat.ModTime()

	// regenerate if cert and key not synced || its been 1 year
	if crtTime.UnixMilli() / 60000 != keyTime.UnixMilli() / 60000 || time.Now().Year() > crtTime.Year() {
		_, err := fs.Copy(crtPath, crtPath+".old")
		if err != nil {
			os.Remove(crtPath+".old")
			return err
		}

		_, err = fs.Copy(keyPath, keyPath+".old")
		if err != nil {
			os.Remove(crtPath+".old")
			os.Remove(keyPath+".old")
			return err
		}

		err = GenRsaKey(crtPath, keyPath)
		if err != nil {
			if _, e := fs.Copy(crtPath+".old", crtPath); e == nil {
				os.Remove(crtPath+".old")
			}

			if _, e := fs.Copy(keyPath+".old", keyPath); e == nil {
				os.Remove(keyPath+".old")
			}

			return err
		}
	}

	return nil
}

// GenRsaKey generates a new ssl certificate and key pair
//  - expires: 3 years
//  - rsa: 4096
//  - x509
//  - sha256
//  - recommended renewal: once a year
func GenRsaKey(crtPath string, keyPath string) error {
	//// 10 years: openssl req -newkey rsa:4096 -x509 -sha256 -days 3650 -nodes -out example.crt -keyout example.key
	// 3 years: openssl req -newkey rsa:4096 -x509 -sha256 -days 1095 -nodes -out example.crt -keyout example.key

	PrintMsg(`warn`, "Generating New SSL Certificate...", 50, false)

	// Generate RSA key
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		PrintMsg(`error`, "Error: Failed To Generate SSL Certificate!", 50, true)
		return err
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	// PEM encoding of private key
	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: keyBytes,
		},
	)

	notBefore := time.Now()
	notAfter := notBefore.Add(365*24*3*time.Hour)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: "localhost"},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// Create certificate using template
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		PrintMsg(`error`, "Error: Failed To Generate SSL Certificate!", 50, true)
		return err
	}

	// pem encoding of certificate
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		},
	)

	// Write key to file
	if err := os.WriteFile(crtPath, certPem, 0600); err != nil {
		PrintMsg(`error`, "Error: Failed To Generate SSL Certificate!", 50, true)
		return err
	}

	// Write cert to file
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		PrintMsg(`error`, "Error: Failed To Generate SSL Certificate!", 50, true)
		return err
	}

	PrintMsg(`warn`, "New SSL Certificate Generated!", 50, true)

	return nil
}

// PrintMsg prints to console and auto inserts spaces
func PrintMsg(color string, msg string, size int, end bool){
	if size > len(msg) {
		msg += strings.Repeat(" ", size-len(msg))
	}

	if color == "none" {
		color = "0"
	}else if color == "error" {
		color = "1;31"
	}else if color == "confirm" {
		color = "1;32"
	}else if color == "warn" {
		color = "1;33"
	}else if color == "info" {
		color = "1;34"
	}else if color == "value" {
		color = "1;35"
	}

	if end {
		fmt.Println("\r\x1b["+color+"m"+msg+"\x1b[0m")
	}else{
		fmt.Print("\r\x1b["+color+"m"+msg+"\x1b[0m")
	}
}
