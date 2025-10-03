package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"SafeCrypt/Explorer"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {

	myApp := app.NewWithID("com.safecrypt.decrypter")
	myWindow := myApp.NewWindow("SafeCrypt Decrypter")

	keyEntry := widget.NewEntry()

	dir := "C:\\Users" // Insert starting directory

	var fixed_files []string
	label_text := "Numer of files to decrypt: "

	numOfFilesLabel := widget.NewLabel(label_text)
	mapFilesButton := widget.NewButton("Map Files", nil)
	decryptButton := widget.NewButton("Decrypt Files", nil)
	progress := widget.NewProgressBar()

	secondTabLabel := widget.NewLabel("This is the log section")

	secondContent := container.NewVBox(
		secondTabLabel,
	)

	progress.Hide()
	decryptButton.Disable()

	mapFilesFunc := func() {
		mapFilesButton.Disable()
		fixed_files = mapFiles(dir)
		if len(fixed_files) == 0 {
			label_text := fmt.Sprintf("Numer of files to decrypt: %d", len(fixed_files))
			numOfFilesLabel.SetText(label_text)
			mapFilesButton.Enable()
			mapFilesButton.Refresh()
			return
		}
		progress.Max = float64(len(fixed_files))
		decryptButton.Enable()
		label_text := fmt.Sprintf("Numer of files to decrypt: %d", len(fixed_files))
		numOfFilesLabel.SetText(label_text)
		mapFilesButton.Enable()
		mapFilesButton.Refresh()
	}
	mapFilesButton.OnTapped = mapFilesFunc

	changeButton := func() {
		decryptButton.Disable()
		progress.Value = 0
		hexKey := keyEntry.Text
		if hexKey == "" {
			decryptButton.Enable()
			return
		}

		key, err := hex.DecodeString(hexKey)
		if err != nil {
			fmt.Println(err)
			return

		}
		keyEntry.SetPlaceHolder("Enter Decryption Key")
		progress.Show()
		go clickButton(fixed_files, key, progress, decryptButton)

		decryptButton.Refresh()
	}
	decryptButton.OnTapped = changeButton

	content := container.NewVBox(
		numOfFilesLabel,
		mapFilesButton,
		widget.NewLabel("Enter decryption key:"),
		keyEntry,
		decryptButton,
		progress,
	)

	tabs := container.NewAppTabs(
		container.NewTabItem("Decryption", content),
		container.NewTabItem("Logs", secondContent),
	)

	myWindow.SetContent(tabs)
	myWindow.Resize(fyne.NewSize(400, 200))
	myWindow.ShowAndRun()

}

func mapFiles(dir string) []string {
	files := Explorer.MapFiles(dir)

	var fixed_files []string

	for _, v := range files {
		if !strings.HasSuffix(v, ".encrypted") {
			continue

		}
		fixed_files = append(fixed_files, v)

	}
	return fixed_files
}

func clickButton(fixed_files []string, key []byte, progress *widget.ProgressBar, decryptButton *widget.Button) {

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
			RunWG(files_of_thread, key, progress)

		}()

		fixed_files = fixed_files[num_of_files_to_add_thread:]

	}

	wg.Wait()
	decryptButton.Enable()
	progress.SetValue(progress.Max)
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		// handle error, e.g. file not found
		return false
	}
	return info.IsDir()
}

func RunWG(files_of_thread []string, key []byte, progress *widget.ProgressBar) {

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

		inFile, err := os.Open(v)
		if err != nil {
			continue
		}
		defer inFile.Close()

		fixedFilename := strings.Split(v, ".encrypted")[0]

		dst, err := os.Create(fixedFilename)
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
			continue
		}

		err = os.Remove(v)
		if err != nil {
			continue
		}
		progress.SetValue(progress.Value + 1)

	}
}
