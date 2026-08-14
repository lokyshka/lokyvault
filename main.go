package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"unicode"

	"golang.org/x/crypto/argon2"
)

func showerr(descr string, err error) {
	fmt.Println("ошибка: ", descr)
	if logging && err != nil {
		fmt.Println(err)
	}
	os.Exit(1)
}

func getpathapp() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		showerr("ошибка получения домашней папки.", err)
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(homedir, "AppData", "Local", "lokyvault", "passwdb.lvdb")
	case "darwin":
		return filepath.Join(homedir, "Library", "Application Support", "lokyvault", "passwdb.lvdb")
	default:
		return filepath.Join(homedir, ".local", "share", "lokyvault", "passwdb.lvdb")
	}
}

const logging bool = true

var pathapp string = getpathapp()
var easypins [70]string = [70]string{
	"000000", "111111", "222222", "333333", "444444",
	"555555", "666666", "777777", "888888", "999999",

	"123456", "234567", "345678", "456789", "567890",
	"678901", "789012", "890123", "901234", "012345",

	"654321", "543210", "432109", "321098", "210987",
	"109876", "098765", "987654", "876543", "765432",

	"101010", "010101", "202020", "020202", "303030",
	"030303", "404040", "040404", "505050", "050505",
	"606060", "060606", "707070", "070707", "808080",
	"080808", "909090", "090909",

	"121212", "212121", "131313", "313131", "141414",
	"414141", "151515", "515151", "161616", "616161",
	"171717", "717171", "181818", "818181", "191919",
	"919191",
}

var chunks = make([]uint16, 10230)
var seed, seed2 uint64
var key, key2, salt []byte

func makevault() {
	err := os.Mkdir(filepath.Dir(pathapp), 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		showerr("ошибка создания папки для хранения данных.", err)
	}
	file, err := os.OpenFile(pathapp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		showerr("ошибка создания базы паролей.", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			showerr("ошибка работы с базой паролей после открытия.", err)
		}
	}()

	noise := make([]byte, 10*1024*1024-16)
	_, err = crand.Read(noise)
	if err != nil {
		showerr("ошибка создания базы данных.", err)
	}

	salt = make([]byte, 16)
	_, err = crand.Read(salt)
	if err != nil {
		showerr("ошибка алгоритма для обработки базы данных паролей.", err)
	}

	vault := make([]byte, 10*1024*1024)
	copy(vault, noise)
	copy(vault[10*1024*1024-16:], salt)

	n, err := file.Write(vault)
	if err != nil || n < len(vault) {
		showerr("ошибка создания базы данных(2).", err)
	}
}

func loadvault(key []byte) {
	/*
		var ciphert, nonce []byte

		for i := range 7000 - 1 { // common passwords
			randnum := rnd1.Uint32N(10230 - 1 - uint32(i))
			ciphert, nonce = readchunk(randnum)
		}

		for i := range 3230 { // secret passwords
			randnum := rnd2.Uint32N(3230 - uint32(i))
			ciphert, nonce = readchunk(randnum)
		}
	*/
}

func getpin(cnt uint8, isnew bool) {
	var pin string

	if isnew {
		fmt.Println("придумайте пин из 6 цифр: ")
	} else {
		fmt.Println("введите пин из 6 цифр: ")
	}
	_, err := fmt.Scan(&pin)
	if err != nil {
		showerr("ошибка ввода. пожалуйста, перезапустите приложение.", err)
	}

	if isnew {
		var pinverif string
		if cnt > 5 {
			showerr("слишком много неподходящих пинов. перезапустите приложение.", nil)
		}
		if len(pin) != 6 {
			fmt.Println("пин должен состоять из 6цифр!")
			getpin(cnt+1, isnew)
			return
		}
		for _, r := range pin {
			if !unicode.IsDigit(r) {
				fmt.Println("пин должен состоять только из цифр!")
				getpin(cnt+1, isnew)
				return
			}
		}
		for _, easypin := range easypins {
			if pin == easypin {
				fmt.Println("пин не должен быть таким простым!")
				getpin(cnt+1, isnew)
				return
			}
		}

		fmt.Print("повторите пин: ")
		_, err := fmt.Scan(&pinverif)
		if err != nil {
			showerr("ошибка ввода. пожалуйста, перезапустите приложение.", err)
		}
		if pin != pinverif {
			fmt.Println("пины не совпадают.")
			getpin(cnt+1, isnew)
			return
		}

		key = genkey(pin, salt)
		seed = hashs(key)
	} else {
		if cnt > 3 {
			showerr("слишком много неудачных попыток.", nil)
		}

		if len(pin) == 12 {
			pin1 := string([]rune(pin)[:6])
			pin2 := pin

			key = genkey(pin1, salt)
			seed = hashs(key)
			rnd1 := mrand.New(mrand.NewPCG(seed, 0))

			randnum := rnd1.Uint32N(10230)
			ciphert, nonce := readchunk(randnum)
			text, err := decr(ciphert, key, nonce)
			if err != nil || text != "lokyvault passwdb" {
				fmt.Println("неверный пин!")
				getpin(cnt+1, isnew)
				return
			}

			for i := range 7000 - 1 { // common passwords
				randnum := rnd1.Uint32N(10230 - 1 - uint32(i))
				chunks = append(chunks[:randnum], chunks[randnum+1:]...)
			}

			key2 = genkey(pin2, salt)
			seed2 = hashs(key2)
			rnd2 := mrand.New(mrand.NewPCG(seed2, 0))

			randnum = rnd2.Uint32N(3230)
			chunks = append(chunks[:randnum], chunks[randnum+1:]...)
			ciphert, nonce = readchunk(randnum)
			text, err = decr(ciphert, key2, nonce)
			if err != nil || text != "lokyvault passwdb" {
				fmt.Println("неверный пин!")
				getpin(cnt+1, isnew)
				return
			}
		} else {
			key = genkey(pin, salt)
			seed = hashs(key)
			rnd := mrand.New(mrand.NewPCG(seed, 0))

			randnum := rnd.Uint32N(10230)
			ciphert, nonce := readchunk(randnum)
			text, err := decr(ciphert, key, nonce)

			if err != nil || text != "lokyvault passwdb" {
				fmt.Println("неверный пин!")
				getpin(cnt+1, isnew)
				return
			}
		}
	}
}

func genkey(pin string, salt []byte) []byte {
	// 3 iteration x 64mb ram x 4threads x aes-256(32bytes key len)
	return argon2.IDKey([]byte(pin), salt, 3, 64*1024, 4, 32)
}

func hashs(key []byte) uint64 {
	sum := sha256.Sum256(key)
	return binary.BigEndian.Uint64(sum[0:8]) ^
		binary.BigEndian.Uint64(sum[8:16]) ^
		binary.BigEndian.Uint64(sum[16:24]) ^
		binary.BigEndian.Uint64(sum[24:32])
}

func getsalt() []byte {
	file, err := os.OpenFile(pathapp, os.O_RDONLY, 0666)
	if err != nil {
		showerr("не удалось открыть базу паролей для получения метаданных.", err)
	}
	defer file.Close()

	salt := make([]byte, 16)
	offset := int64(10*1024*1024 - 16)
	_, err = file.ReadAt(salt, offset)
	if err != nil {
		showerr("ошибка в чтении дополнительных данных базы паролей.", err)
	}
	return salt
}

func readchunk(chnk uint32) ([]byte, []byte) {
	file, err := os.OpenFile(pathapp, os.O_RDONLY, 0666)
	if err != nil {
		showerr("не удалось открыть базу паролей для получения метаданных.", err)
	}
	defer file.Close()

	data := make([]byte, 1024)
	offset := int64(chnk * 1024)
	_, err = file.ReadAt(data, offset)
	if err != nil {
		showerr("ошибка чтении данных в базе паролей.", err)
	}

	nonce := data[:12]
	ciphert := data[12:]
	return ciphert, nonce
}

func writechunk(chnk uint32, data []byte) {
	file, err := os.OpenFile(pathapp, os.O_WRONLY, 0666)
	if err != nil {
		showerr("не удалось открыть базу паролей.", err)
	}
	defer file.Close()

	offset := int64(chnk * 1024)
	_, err = file.WriteAt(data, offset)
	if err != nil {
		showerr("ошибка записи данных в базу паролей.", err)
	}
}

func encr(text string, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		showerr("ошибка подготовки данных к шифрованию.", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerr("ошибка подготовки данных к шифрованию 2.", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = crand.Read(nonce)
	if err != nil {
		showerr("ошибка подготовки данных к шифрованию 3.", err)
	}

	nsize := gcm.NonceSize() // 12bits
	ohsize := gcm.Overhead() // 16bits

	ciphert := make([]byte, nsize, 1024)
	copy(ciphert, nonce)

	btext := make([]byte, 1024-nsize-ohsize)
	copy(btext[:], []byte(text))

	ciphert = gcm.Seal(ciphert[:], nonce, btext, nil)
	return ciphert
}

func decr(ciphert []byte, key []byte, nonce []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		showerr("ошибка подготовки данных к шифрованию.", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerr("ошибка подготовки данных к шифрованию 2.", err)
	}

	text, err := gcm.Open(nil, nonce, ciphert, nil)
	if err != nil {
		return "", fmt.Errorf("ошибка расшифровки или неверный ключ: %w", err)
	}

	text = bytes.TrimRight(text, "\x00")
	return string(text), nil
}

func init() {
	for i := range 10230 {
		chunks[i] = uint16(i)
	}
	_, err := os.Stat(pathapp)
	if err == nil {
		salt = getsalt()
		getpin(0, false)

		// ...

		loadvault(key)
	} else if errors.Is(err, os.ErrNotExist) {
		makevault()
		getpin(0, true)
		towrite := encr("lokyvault passwdb", key)

		rnd := mrand.New(mrand.NewPCG(seed, 0))
		randnum := rnd.Uint32N(10230)

		writechunk(randnum, towrite)
	} else {
		showerr("не удалось получить информацию о состоянии базу паролей.", err)
	}
}

func main() {
	fmt.Println("here is interface!(it's empty now)")
}
