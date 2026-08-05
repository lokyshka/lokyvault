package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/argon2"
)

func getpathapp() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("Ошибка:", err)
		os.Exit(0)
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(homedir, "AppData", "Local", "lokyvault")
	case "darwin":
		return filepath.Join(homedir, "Library", "Application Support", "lokyvault")
	default:
		return filepath.Join(homedir, ".local", "share", "lokyvault")
	}
}

var pathapp string = getpathapp()

func makevault() {
	file, err := os.Create(filepath.Join(pathapp, "passwdb.lvdb"))
	if err != nil {
		fmt.Println("Ошибка:", err)
		os.Exit(0)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Println("Ошибка:", err)
			os.Exit(0)
		}
	}()

	noise := make([]byte, 10*1024*1024)
	_, err = rand.Read(noise)
	if err != nil {
		fmt.Println("Ошибка:", err)
		os.Exit(0)
	}

	n, err := file.Write(noise)
	if err != nil || n < len(noise) {
		fmt.Printf("Ошибка при записи: %v\n", err)
		return
	}
}

func genkey(pin string, salt []byte) []byte {
	// 1 итерация
	// 64mb ram
	// 4threads
	// 32bytes(aes256) key length
	return (argon2.IDKey([]byte(pin), salt, 1, 64*1024, 4, 32))
}
