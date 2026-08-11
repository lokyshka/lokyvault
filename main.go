package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	crand "crypto/rand"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
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

var chunks [10240]uint16
var seed, seed2 uint64
var key, key2 []byte

func makevault() {
	err := os.Mkdir(filepath.Dir(pathapp), 0755)
	if err != nil && !errors.Is(err, os.ErrExist) {
		showerr("ошибка создания папки дял хранения данных.", err)
	}
	file, err := os.Create(pathapp)
	if err != nil {
		showerr("ошибка создания базы паролей.", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			showerr("ошибка работы с базой паролей после открытия.", err)
		}
	}()

	noise := make([]byte, 10*1024*1024)
	_, err = crand.Read(noise)
	if err != nil {
		showerr("ошибка создания базы данных.", err)
	}

	n, err := file.Write(noise)
	if err != nil || n < len(noise) {
		showerr("ошибка создания базы данных(2).", err)
	}
}

func getpin(cnt uint8, isnew bool) string {
	var pin, pinverif string
	if isnew {
		fmt.Println("придумайте пин из 6 цифр: ")
	} else {
		fmt.Println("введите пин из 6 цифр: ")
	}
	if _, err := fmt.Scan(&pin); err != nil {
		showerr("ошибка ввода. пожалуйста, перезапустите приложение.", nil)
	}
	if isnew {
		if cnt > 5 {
			showerr("слишком много неподходящих пинов. перезапустите приложение.", nil)
		}
		if len(pin) != 6 {
			fmt.Println("пин должен состоять из 6цифр!")
			return getpin(cnt+1, isnew)
		}
		for _, r := range pin {
			if !unicode.IsDigit(r) {
				fmt.Println("пин должен состоять только из цифр!")
				return getpin(cnt+1, isnew)
			}
		}
		for _, easypin := range easypins {
			if pin == easypin {
				fmt.Println("пин не должен быть таким простым!")
				return getpin(cnt+1, isnew)
			}
		}

		fmt.Print("повторите пин: ")
		if _, err := fmt.Scan(&pinverif); err != nil {
			showerr("ошибка ввода. пожалуйста, перезапустите приложение.", nil)
		}
		if pin != pinverif {
			fmt.Println("пины не совпадают.")
			return getpin(cnt+1, isnew)
		}
	} else {
		if cnt > 3 {
			showerr("слишком много неверных пинов.", nil)
		}
		if len(pin) == 12 {
			pin1 := string([]rune(pin)[:6])
			pin2 := string([]rune(pin)[6:])

			h := fnv.New64a()
			h.Write([]byte(pin1))
			seed = h.Sum64()

			rnd1 := mrand.New(mrand.NewPCG(seed, 0))

			h = fnv.New64a()
			h.Write([]byte(pin2))
			seed2 = h.Sum64()

			rnd2 := mrand.New(mrand.NewPCG(seed2, 0))
			fmt.Println(rnd2) // temp
			// randnum = rnd1.Int32N(10240)

			for _ = range 7000 { // to-do, bad algorithm
				randnum := rnd1.Int32N(10240)
				if chunks[randnum] == 18000 {
					randnum = rnd1.Int32N(10240)
				}
				chunks[randnum] = 18000
			}
		}
	}
	return pin
}

func genkey(pin string, salt []byte) []byte {
	// 1 итерация
	// 64mb ram
	// 4threads
	// 32bytes(aes256) key length
	return (argon2.IDKey([]byte(pin), salt, 1, 64*1024, 4, 32))
}

func encr(text string, key []byte, salt []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		showerr("ошибка подготовки данных к шифрованию.", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerr("ошибка подготовки данных к шифрованию 2.", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		showerr("ошибка подготовки данных к шифрованию 3.", err)
	}

	var b [1024]byte
	copy(b[:], []byte(text))
	ciphert := gcm.Seal(nonce, nonce, []byte(text), nil)

	result := make([]byte, len(salt)+len(ciphert))
	copy(result, salt)
	copy(result[len(salt):], ciphert)

	return result
}

func init() {
	for i := range 10240 {
		chunks[i] = uint16(i)
	}
	_, err := os.Stat(pathapp)
	if err == nil {
		return
	} else if errors.Is(err, os.ErrNotExist) {
		makevault()
		pin := getpin(0, true)

		salt := make([]byte, 16)
		_, err := rand.Read(salt)
		if err != nil {
			showerr("ошибка алгоритма для обработки базы данных паролей.", err)
		}
		key = genkey(pin, salt)

		h := fnv.New64a()
		h.Write([]byte(pin))
		seed = h.Sum64()

		rnd := mrand.New(mrand.NewPCG(seed, 0))
		randnum := rnd.Int32N(10240)

		writebuf := encr("lokyvault passwdb", key, salt)

		file, err := os.OpenFile(pathapp, os.O_RDWR, 0666)
		if err != nil {
			showerr("не удалось открыть базу паролей.", err)
		}
		defer file.Close()

		offset := int64(randnum * 1024)
		_, err = file.WriteAt(writebuf, offset)
		if err != nil {
			showerr("ошибка записи данных в базу паролей", err)
		}
	} else {
		showerr("не удалось получить информацию о состоянии базу паролей.", err)
	}
}

func main() {
	fmt.Println("here is interface!(it's empty now)")
}
