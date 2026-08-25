package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ncruces/zenity"
	"golang.org/x/crypto/argon2"
)

func showerrf(descr string, err error) {
	if logging && err != nil {
		fmt.Println(err)
	}

	errdialog := dialog.NewError(errors.New(" "+descr), window)
	errdialog.SetOnClosed(func() {
		window.Close()
		os.Exit(1)
	})
	errdialog.Show()
}

func showerr(descr string) {
	dialog.ShowError(errors.New(" "+descr), window)
}

func showoverl(text string, result func(bool)) {
	confirm := dialog.NewConfirm(
		"",
		text,
		result,
		window,
	)

	confirm.SetConfirmText("да")
	confirm.SetDismissText("нет")
	confirm.Show()
}

func wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

func isempty(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}

func maxsliceval(s []uint16) uint16 {
	if len(s) == 0 {
		return 0
	}
	max := s[0]
	for _, v := range s[1:] {
		if v > max {
			max = v
		}
	}
	return max
}

func freech(issecr bool) uint16 {
	var idx uint16 = 65535
	var ls []uint16
	if issecr {
		ls = chunks2
	} else {
		ls = chunks1
	}
	for i := range 30700 {
		if freechunks[i] {
			for _, item := range ls {
				if item == uint16(i) {
					idx = uint16(i)
					break
				}
			}
		}
	}
	return idx
}

func logout() {
	wipe(key)
	wipe(key2)
	key = nil
	key2 = nil
	seed = [2]uint64{0, 0}
	seed2 = [2]uint64{0, 0}

	vault = make([]lvault, 0)
	chunks1 = make([]uint16, 7000-1)
	chunks2 = make([]uint16, 30700)
	freechunks = make([]bool, 30700)

	_, err := os.Stat(pathapp)
	if err == nil {
		getsalt()
		auth(false)
	} else if errors.Is(err, os.ErrNotExist) {
		makesalt()
		auth(true)
	} else {
		showerrf("не удалось получить информацию о состоянии базы паролей.", err)
	}
}

func loadicon(nameicon string) *fyne.StaticResource {
	themecur := "-light"

	if fyne.CurrentApp().Settings().ThemeVariant() == theme.VariantDark {
		themecur = "-dark"
	}
	path := filepath.Join("assets", nameicon+themecur+".png")
	data, err := icons.ReadFile(path)
	if err != nil {
		return nil
	}

	icon := fyne.NewStaticResource(nameicon, data)
	return icon
}

func getpathapp() string {
	homedir, err := os.UserHomeDir()
	if err != nil {
		showerrf("ошибка получения домашней папки.", err)
	}
	switch runtime.GOOS {
	case "windows":
		if !logging {
			devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err == nil {
				os.Stdout = devnull
				os.Stderr = devnull
			}
		}
		return filepath.Join(homedir, "AppData", "Local", "lokyvault", "passwdb.lvault")
	case "darwin":
		return filepath.Join(homedir, "Library", "Application Support", "lokyvault", "passwdb.lvault")
	default:
		return filepath.Join(homedir, ".local", "share", "lokyvault", "passwdb.lvault")
	}
}

//go:embed assets/*.png
var icons embed.FS

type lvault struct {
	title  string
	site   string
	usern  string // username
	datec  string // date of creation
	datee  string // date of last edition
	isfav  bool   // is password favourite
	issecr bool   // is password secret
	chunk  uint16 // chunk number
}
type clicklab struct {
	widget.Label
	ontap func()
}

const logging bool = false
const version string = "v1.0-beta"

var appl = app.NewWithID("com.lokyvault.app")
var window = appl.NewWindow("lokyvault | менеджер паролей")
var stopticklogout chan struct{} = make(chan struct{})
var pathapp string = getpathapp()

var vault = make([]lvault, 0)
var chunks1 = make([]uint16, 7000-1)
var chunks2 = make([]uint16, 30700)
var freechunks = make([]bool, 30700)
var seed, seed2 [2]uint64
var key, key2, salt []byte
var lstactivity time.Time

func makevault() {
	err := os.MkdirAll(filepath.Dir(pathapp), 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		showerrf("ошибка создания папки для хранения данных.", err)
	}

	file, err := os.OpenFile(pathapp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		showerrf("ошибка создания базы паролей.", err)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			showerrf("ошибка работы с базой паролей после открытия.", err)
		}
	}()

	noise := make([]byte, 30*1024*1024-16)
	_, err = crand.Read(noise)
	if err != nil {
		showerrf("ошибка создания базы данных.", err)
	}

	data := make([]byte, 30*1024*1024)
	copy(data, noise)
	copy(data[30*1024*1024-16:], salt)

	n, err := file.Write(data)
	if err != nil || n < len(data) {
		showerrf("ошибка создания базы данных(2).", err)
	}

	towrite := encr([]byte("lokyvault passwdb"), key)

	rnd1 := mrand.New(mrand.NewPCG(seed[0], seed[1]))
	randnum := rnd1.Uint32N(30700)
	writechunk(uint16(randnum), towrite, file)

	towrite = encr([]byte("lokyvault passwdb"), key2)

	rnd2 := mrand.New(mrand.NewPCG(seed2[0], seed2[1]))
	randnum = rnd2.Uint32N(23700)
	writechunk(chunks2[randnum], towrite, file)

	chunks2[randnum] = chunks2[len(chunks2)-1]
	chunks2 = chunks2[:len(chunks2)-1]
}

func importvault(isnew *bool) func() {
	return func() {
		path, err := zenity.SelectFile(
			zenity.Title("выберите файл хранилища паролей"),
			zenity.FileFilter{
				Name:     "файлы lokyvault (*.lvault)",
				Patterns: []string{"*.lvault"},
			},
		)

		if errors.Is(err, zenity.ErrCanceled) {
			return
		}

		if err != nil {
			showerr("не удалось импортировать выбранный файл.")
			return
		}

		file, err := os.OpenFile(path, os.O_RDONLY, 0600)
		if err != nil {
			showerr("не удалось импортировать выбранный файл.")
			return
		}
		defer file.Close()

		err = os.MkdirAll(filepath.Dir(pathapp), 0700)
		if err != nil {
			showerr("не удалось импортировать выбранный файл.")
			return
		}

		appvault, err := os.OpenFile(pathapp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			showerr("не удалось импортировать выбранный файл.")
			return
		}
		defer appvault.Close()

		_, err = io.Copy(appvault, file)
		if err != nil {
			showerr("не удалось импортировать выбранный файл.")
			return
		}

		err = appvault.Close()
		if err != nil {
			showerr("не удалось импортировать выбранный файл.")
			return
		}

		*isnew = false
		logout()
	}
}

func exportvault() func() {
	return func() {
		path, err := zenity.SelectFileSave(
			zenity.Title("выберите, куда сохранить файл хранилища паролей"),
			zenity.Filename("passwdb.lvault"),
			zenity.FileFilter{
				Name:     "файлы lokyvault (*.lvault)",
				Patterns: []string{"*.lvault"},
			},
			zenity.ConfirmOverwrite(),
		)

		if errors.Is(err, zenity.ErrCanceled) {
			return
		}

		if err != nil {
			showerr("не удалось экспортировать хранилище.")
			return
		}

		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			showerr("не удалось экспортировать хранилище.")
			return
		}
		defer file.Close()

		appvault, err := os.OpenFile(pathapp, os.O_RDONLY, 0600)
		if err != nil {
			showerr("не удалось экспортировать хранилище.")
			return
		}
		defer appvault.Close()

		_, err = io.Copy(file, appvault)
		if err != nil {
			showerr("не удалось экспортировать хранилище.")
			return
		}

		err = file.Close()
		if err != nil {
			showerr("не удалось экспортировать хранилище.")
			return
		}
	}
}

func loadchunk(chunk uint16, file *os.File, issecr, ispasswd bool) []byte {
	var curkey []byte
	ciphert, nonce := readchunk(chunk, file)
	if ciphert == nil || nonce == nil {
		return nil
	}
	if issecr {
		curkey = key2
	} else {
		curkey = key
	}
	text, err := decr(ciphert, curkey, nonce)
	if err != nil {
		freechunks[chunk] = true
		return nil
	}

	data, passwd := unpack(text, chunk, ispasswd, issecr)

	if ispasswd {
		return passwd
	}

	vault = append(vault, data)
	return nil
}

func loadvault() {
	file, err := os.OpenFile(pathapp, os.O_RDONLY, 0666)
	if err != nil {
		showerrf("ошибка чтения объекта.", err)
		return
	}
	defer file.Close()

	for _, chunk := range chunks1 {
		loadchunk(chunk, file, false, false)
	}
	if !isempty(key2) {
		for _, chunk := range chunks2 {
			loadchunk(chunk, file, true, false)
		}
	}
}

func checkpin(pin []byte) bool {
	var isletter bool
	var r rune
	var size int
	if utf8.RuneCount(pin) < 8 {
		showerr("длина пина должна быть от 8 символов(буквы обязательны, можно цифры и спецсимволы)!\nвозможно, у вас выбрана неверная раскладка клавиатуры.")
		return false
	}

	/* for _, easypin := range easypins {
		if pin == easypin {
			showerr("пин не должен быть таким простым!"
			return
		}
	} */

	for i := 0; i < len(pin); {
		r, size = utf8.DecodeRune(pin[i:])
		if (r == utf8.RuneError && size == 1) || unicode.IsSpace(r) {
			showerr("вы ввели недопустимые символы!")
			return false
		}
		if unicode.IsLetter(r) {
			isletter = true
		}
		i += size
	}
	if !isletter {
		showerr("пин должен содержать в себе буквы!")
		return false
	}
	return true
}

func auth(isnew bool) {
	var texth, textd string
	var pin, pin1 []byte
	var cnt uint8
	var expimpvault fyne.CanvasObject

	if isnew {
		texth = "# добро пожаловать в lokyvault!"
		textd = "придумайте пин длиной от 8 символов для шифрования хранилища паролей.\nбуквы обязательны, цифры и спецсимволы разрешены."
	} else {
		texth = "# хранилище защищено"
		textd = "введите пин, чтобы снять защиту."
	}

	header := widget.NewRichTextFromMarkdown(texth)
	label := widget.NewLabelWithStyle(textd, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	label.Wrapping = fyne.TextWrapWord
	verlab := widget.NewLabel(version)

	letsgob := widget.NewButton("", func() { premainui(isnew) })
	letsgob.Hide()

	entry := widget.NewPasswordEntry()
	entrycont := container.NewGridWrap(fyne.NewSize(300, 40), entry)
	entry.SetPlaceHolder("введите пин")

	if isnew {
		var fstpin, fstpin2 []byte
		var fstdone bool
		expimpvault = widget.NewButton("  импорт  ", importvault(&isnew))

		chunks1 = make([]uint16, 7000-1)
		chunks2 = make([]uint16, 30700)
		for i := range 30700 {
			chunks2[i] = uint16(i)
		}
		freechunks = make([]bool, 30700)

		entry.OnSubmitted = func(s string) {
			pin = []byte(entry.Text)
			entry.SetText("")
			cnt++
			if cnt > 5 {
				showerrf("слишком много неудачных попыток. перезапустите приложение.", nil)
			}

			if !fstdone {
				if isempty(fstpin) {
					if !checkpin(pin) {
						wipe(pin)
						return
					}
					fstpin = make([]byte, len(pin))
					copy(fstpin, pin)
					wipe(pin)

					label.SetText("повторите пин.")
					return
				}

				if !bytes.Equal(fstpin, pin) {
					wipe(fstpin)
					wipe(pin)
					showerr("пины не совпадают! попробуйте снова.")
					label.SetText(textd)
					return
				}

				key = genkey(pin, salt)
				wipe(pin)
				seed = hashs(key)
				rnd1 := mrand.New(mrand.NewPCG(seed[0], seed[1]))

				randnum := rnd1.Uint32N(30700)
				chunks2[randnum] = chunks2[len(chunks2)-1]
				chunks2 = chunks2[:len(chunks2)-1]

				for i := range 7000 - 1 {
					randnum = rnd1.Uint32N(30700 - 1 - uint32(i))
					chunks1[i] = chunks2[randnum]
					chunks2[randnum] = chunks2[len(chunks2)-1]
					chunks2 = chunks2[:len(chunks2)-1]
				}

				cnt = 0
				fstdone = true
				header.ParseMarkdown("# создание секретного раздела")
				label.SetText("придумайте новый пароль для секретного хранилища.")
				letsgob.SetText("пропустить")
				letsgob.Show()
				expimpvault.Hide()
				return
			}

			if isempty(fstpin2) {
				if bytes.Equal(fstpin, pin) {
					showerr("пины не могут быть одинаковыми!")
					wipe(pin)
					return
				}
				if !checkpin(pin) {
					wipe(pin)
					return
				}

				fstpin2 = make([]byte, len(pin))
				copy(fstpin2, pin)
				wipe(pin)

				label.SetText("повторите 2-ой пин.")
				return
			}

			if !bytes.Equal(fstpin2, pin) {
				wipe(fstpin2)
				wipe(pin)
				showerr("пины не совпадают! попробуйте снова.")
				label.SetText(textd)
				return
			}

			wipe(fstpin2)
			pin1 := make([]byte, len(fstpin)+len(pin))
			copy(pin1, fstpin)
			copy(pin1[len(fstpin):], pin)
			wipe(pin)
			wipe(fstpin)

			key2 = genkey([]byte(pin1), salt)
			wipe(pin1)
			seed2 = hashs(key2)

			header.ParseMarkdown("# готово!")
			label.SetText("чтобы зайти в секретное хранилище, введите оба пароля, поставив между ними пробел.")
			entry.Hide()
			letsgob.SetText("открыть хранилище")
			letsgob.Show()
		}
	} else {
		var issecr bool
		var pinbad []byte
		expimpvault = widget.NewButton("  экспорт  ", exportvault())
		entry.OnSubmitted = func(s string) {
			pinbad = []byte(entry.Text)
			entry.SetText("")
			cnt++
			if cnt > 3 {
				showerrf("слишком много неудачных попыток.", nil)
				return
			}

			spaceidx := bytes.IndexByte(pinbad, ' ')
			if spaceidx != -1 {
				pin = make([]byte, len(pinbad)-1)
				copy(pin, pinbad[:spaceidx])
				copy(pin[spaceidx:], pinbad[spaceidx+1:])
				wipe(pinbad)
				pin1 = pin[:spaceidx]
				issecr = true
			} else {
				pin1 = make([]byte, len(pinbad))
				copy(pin1, pinbad)
				wipe(pinbad)
			}

			key = genkey([]byte(pin1), salt)
			if issecr {
				key2 = genkey([]byte(pin), salt)
			}
			wipe(pin)
			seed = hashs(key)
			rnd1 := mrand.New(mrand.NewPCG(seed[0], seed[1]))

			randnum := rnd1.Uint32N(30700)
			ciphert, nonce := readchunk(uint16(randnum), nil)
			if ciphert == nil || nonce == nil {
				return
			}
			txt, err := decr(ciphert, key, nonce)

			if err != nil || !bytes.Equal(txt, []byte("lokyvault passwdb")) {
				showerr("неверный пин!(возможно, выбрана неверная раскладка клавиатуры)")
				return
			}

			chunks1 = make([]uint16, 7000-1)
			chunks2 = make([]uint16, 30700)
			for i := range 30700 {
				chunks2[i] = uint16(i)
			}
			freechunks = make([]bool, 30700)
			chunks2[randnum] = chunks2[len(chunks2)-1]
			chunks2 = chunks2[:len(chunks2)-1]

			for i := range 7000 - 1 {
				randnum = rnd1.Uint32N(30700 - 1 - uint32(i))
				chunks1[i] = chunks2[randnum]
				chunks2[randnum] = chunks2[len(chunks2)-1]
				chunks2 = chunks2[:len(chunks2)-1]
			}

			if issecr {
				seed2 = hashs(key2)
				rnd2 := mrand.New(mrand.NewPCG(seed2[0], seed2[1]))

				randnum = rnd2.Uint32N(23700)
				ciphert, nonce = readchunk(chunks2[randnum], nil)
				if ciphert == nil || nonce == nil {
					return
				}
				txt, err = decr(ciphert, key2, nonce)

				if err != nil || !bytes.Equal(txt, []byte("lokyvault passwdb")) {
					showerr("неверный пин!(возможно, выбрана неверная раскладка клавиатуры)")
					return
				}
				chunks2[randnum] = chunks2[len(chunks2)-1]
				chunks2 = chunks2[:len(chunks2)-1]
			}
			premainui(isnew)
		}
	}

	login := container.NewCenter(
		container.NewVBox(
			header,
			label,
			container.NewCenter(entrycont),
			letsgob,
		),
	)
	righttop := container.NewBorder(
		nil,
		nil,
		nil,
		container.NewPadded(
			container.NewHBox(expimpvault),
		),
		nil,
	)

	rightdown := container.NewPadded(
		container.NewHBox(verlab),
	)

	content := container.NewStack(
		login,
		container.NewBorder(righttop, rightdown, nil, nil, nil),
	)
	window.SetContent(content)
}

func genkey(pin, salt []byte) []byte {
	// 5 iteration x 64mb ram x 4threads x 32bytes(256bits) key len
	return argon2.IDKey([]byte(pin), salt, 5, 64*1024, 4, 32)
}

func hashs(key []byte) [2]uint64 {
	sum := sha256.Sum256(key)
	return [2]uint64{
		binary.BigEndian.Uint64(sum[0:8]),
		binary.BigEndian.Uint64(sum[8:16]),
	}
}

func makesalt() {
	salt = make([]byte, 16)
	_, err := crand.Read(salt)
	if err != nil {
		showerrf("ошибка алгоритма для обработки базы данных паролей.", err)
	}
}

func getsalt() {
	file, err := os.OpenFile(pathapp, os.O_RDONLY, 0666)
	if err != nil {
		showerrf("не удалось открыть базу паролей для получения метаданных.", err)
	}
	defer file.Close()

	salt = make([]byte, 16)
	offset := int64(30*1024*1024 - 16)
	_, err = file.ReadAt(salt, offset)
	if err != nil {
		showerrf("ошибка в чтении дополнительных данных базы паролей.", err)
	}
}

func readchunk(chnk uint16, file *os.File) ([]byte, []byte) {
	var err error
	if file == nil {
		file, err = os.OpenFile(pathapp, os.O_RDONLY, 0666)
		if err != nil {
			showerr("ошибка чтения объекта.")
			return nil, nil
		}
		defer file.Close()
	}

	data := make([]byte, 1024)
	offset := int64(chnk) * 1024
	_, err = file.ReadAt(data, offset)
	if err != nil {
		showerr("ошибка чтения объекта.")
		return nil, nil
	}

	nonce := data[:12]
	ciphert := data[12:]
	return ciphert, nonce
}

func writechunk(chnk uint16, data []byte, file *os.File) {
	var err error
	if file == nil {
		file, err = os.OpenFile(pathapp, os.O_WRONLY, 0666)
		if err != nil {
			showerr("ошибка записи объекта.")
			return
		}
		defer func() {
			err := file.Close()
			if err != nil {
				showerr("ошибка записи объекта.")
				return
			}
		}()
	}

	offset := int64(chnk) * 1024
	_, err = file.WriteAt(data, offset)
	if err != nil {
		showerr("ошибка записи объекта.")
		return
	}
}

func delchunk(chnk uint16) {
	noise := make([]byte, 1024)
	_, err := crand.Read(noise)
	if err != nil {
		showerr("ошибка удаления объекта.")
		return
	}
	writechunk(chnk, noise, nil)
}

func encr(text, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию.", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию 2.", err)
	}

	maxdatalen := 1024 - 12 - gcm.Overhead()

	if len(text) > maxdatalen-2 {
		showerrf("слишком большой ввод!", nil)
	}

	nonce := make([]byte, 12)
	_, err = crand.Read(nonce)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию 3.", err)
	}

	datalen := uint16(len(text) + 2)
	datalenb := make([]byte, 2)
	binary.BigEndian.PutUint16(datalenb, datalen)

	btext := make([]byte, maxdatalen)
	copy(btext, datalenb)
	copy(btext[2:], text)
	wipe(text)

	ciphert := gcm.Seal(nonce, nonce, btext, nil)

	wipe(btext)
	return ciphert
}

func decr(ciphert, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию.", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию 2.", err)
	}

	btext, err := gcm.Open(nil, nonce, ciphert, nil)
	if err != nil {
		return nil, err
	}

	datalen := binary.BigEndian.Uint16(btext[:2])
	text := btext[2:datalen]
	return text, nil
}

func pack(data lvault, passwd []byte) []byte {
	var lencur, length uint16
	var titlet, sitet, usernt, datect, dateet []byte
	titlet = []byte(data.title)
	sitet = []byte(data.site)
	usernt = []byte(data.usern)
	datect = []byte(data.datec)
	dateet = []byte(data.datee)
	timenow := time.Now().Format("02.01.2006 15:04")

	if isempty(titlet) {
		titlet = make([]byte, 1)
	}
	if isempty(sitet) {
		sitet = make([]byte, 1)
	}
	if isempty(usernt) {
		usernt = make([]byte, 1)
	}
	if isempty(datect) {
		datect = []byte(timenow)
	}
	if isempty(dateet) {
		dateet = []byte(timenow)
	}
	if isempty(passwd) {
		passwd = make([]byte, 1)
	}
	var lenfull uint16 = uint16(
		len(titlet) +
			len(sitet) +
			len(usernt) +
			len(passwd) +
			len(datect) +
			len(dateet) + 13)
	btext := make([]byte, lenfull)

	lencur = uint16(len(titlet))
	binary.BigEndian.PutUint16(btext, lencur)
	copy(btext[length+2:], titlet)
	length += lencur + 2

	lencur = uint16(len(sitet))
	binary.BigEndian.PutUint16(btext[length:], lencur)
	copy(btext[length+2:], sitet)
	length += lencur + 2

	lencur = uint16(len(usernt))
	binary.BigEndian.PutUint16(btext[length:], lencur)
	copy(btext[length+2:], usernt)
	length += lencur + 2

	lencur = uint16(len(datect))
	binary.BigEndian.PutUint16(btext[length:], lencur)
	copy(btext[length+2:], datect)
	length += lencur + 2

	lencur = uint16(len(dateet))
	binary.BigEndian.PutUint16(btext[length:], lencur)
	copy(btext[length+2:], dateet)
	length += lencur + 2

	if data.isfav {
		btext[length] = 1
	}
	length++

	lencur = uint16(len(passwd))
	binary.BigEndian.PutUint16(btext[length:], lencur)
	copy(btext[length+2:], passwd)
	wipe(passwd)

	return btext
}

func unpack(btext []byte, chunknum uint16, ispasswd, issecr bool) (lvault, []byte) {
	var lencur, length uint16
	var data lvault
	var passwd []byte

	if len(btext) < 2 {
		showerr("произошла ошибка при разбивке чанка!")
		return data, nil
	}

	lencur = binary.BigEndian.Uint16(btext[0:2]) + 2
	data.title = string(btext[2:lencur])
	length += lencur

	if int(lencur) > len(btext) {
		showerr("произошла ошибка при разбивке чанка!")
		return data, nil
	}

	lencur = binary.BigEndian.Uint16(btext[length:length+2]) + 2
	data.site = string(btext[length+2 : length+lencur])
	length += lencur

	lencur = binary.BigEndian.Uint16(btext[length:length+2]) + 2
	data.usern = string(btext[length+2 : length+lencur])
	length += lencur

	lencur = binary.BigEndian.Uint16(btext[length:length+2]) + 2
	data.datec = string(btext[length+2 : length+lencur])
	length += lencur

	lencur = binary.BigEndian.Uint16(btext[length:length+2]) + 2
	data.datee = string(btext[length+2 : length+lencur])
	length += lencur

	if btext[length] == 1 {
		data.isfav = true
	}
	length++

	if ispasswd {
		lencur = binary.BigEndian.Uint16(btext[length:length+2]) + 2
		passwd = btext[length+2 : length+lencur]
		write := 0
		for _, b := range passwd {
			if b != 0 {
				passwd[write] = b
				write++
			}
		}
		passwd = passwd[:write]
	} else {
		lencur = binary.BigEndian.Uint16(btext[length:length+2]) + 2
		wipe(btext[length+2 : length+lencur])
		passwd = nil
	}

	data.title = strings.ReplaceAll(data.title, "\x00", "")
	data.site = strings.ReplaceAll(data.site, "\x00", "")
	data.usern = strings.ReplaceAll(data.usern, "\x00", "")
	data.datec = strings.ReplaceAll(data.datec, "\x00", "")
	data.datee = strings.ReplaceAll(data.datee, "\x00", "")
	data.chunk = chunknum
	data.issecr = issecr

	return data, passwd
}

func writeobj(data lvault, passwdt []byte, seld uint16) bool {
	var isnew bool
	timenow := time.Now().Format("02.01.2006 15:04")
	if data.chunk == 65535 {
		data.chunk = freech(data.issecr)
	}
	if data.datec == "" {
		data.datec = timenow
		isnew = true
	}
	if data.datee == "" {
		data.datee = timenow
	} else if seld == 65535 {
		showerr("ошибка записи обьекта!")
	}

	if data.title == "" || isempty(passwdt) {
		wipe(passwdt)
		showerr("поля заглавия и пароля обязательны!")
		return false
	}

	length := len(data.title) + len(data.site) +
		len(data.usern) + len(passwdt) +
		len(data.datec) + len(data.datee)
	if length >= 992 {
		wipe(passwdt)
		showerr("слишком длинные данные!")
		return false
	}

	if isnew {
		vault = append(vault, data)
	} else {
		vault[seld] = data
	}
	packed := pack(data, passwdt)
	var encrdata []byte
	if data.issecr {
		encrdata = encr(packed, key2)
	} else {
		encrdata = encr(packed, key)
	}

	wipe(packed)
	writechunk(data.chunk, encrdata, nil)
	return true
}

func (c *clicklab) Tapped(e *fyne.PointEvent) {
	if c.ontap != nil {
		c.ontap()
	}
}

func newclicklab(text string, funct func()) *clicklab {
	lab := &clicklab{ontap: funct}
	lab.Text = text
	lab.ExtendBaseWidget(lab)
	return lab
}

func newentry() (*widget.Entry, *fyne.Container) {
	entry := widget.NewEntry()
	entry.Wrapping = fyne.TextWrapOff
	entry.Scroll = fyne.ScrollNone
	entrycont := container.NewGridWrap(fyne.NewSize(200, 30), entry)
	return entry, entrycont
}

func seticon(button *widget.Button, nameicon string) {
	var text string
	switch nameicon {
	case "logout":
		text = " ⏏ "
	case "secr":
		text = " 👁 "
	case "secr-chd":
		text = " 👁️‍🗨️ "
	case "add":
		text = " + "
	case "edit":
		text = " ✎ "
	case "fav":
		text = " ☆ "
	case "fav-chd":
		text = " ★ "
	case "move":
		text = " ⤭ "
	case "share":
		text = " ⤴ "
	case "del":
		text = " — "
	}

	icon := loadicon(nameicon)
	if icon == nil {
		button.SetText(text)
	} else {
		button.SetIcon(icon)
	}
}

func getpasswd(chunk uint16, issecr bool) []byte {
	return loadchunk(chunk, nil, issecr, true)
}

func clipb(text string) {
	appl.Clipboard().SetContent(text)
	dialog.ShowInformation("", "данные были скопированы в буфер обмена.", window)
}

func clipbpasswd(chunk uint16, issecr bool, label *widget.Label, timer **time.Timer) {
	passwd := getpasswd(chunk, issecr)
	if label.Text == "********" || label.Text == "" {
		label.Text = string(passwd)
		label.Refresh()
	} else {
		appl.Clipboard().SetContent(string(passwd))
		dialog.ShowInformation("", "пароль был скопирован в буфер обмена.\nчерез 5 минут буфер обмена будет очищен.", window)

		if *timer != nil {
			(*timer).Stop()
		}
		*timer = time.AfterFunc(5*time.Minute, func() {
			appl.Clipboard().SetContent("")
		})
	}
}

func premainui(isnew bool) {
	if isnew {
		makevault()
	}

	loadvault()
	mainui()
}

func mainui() {
	var seld uint16 = 65535
	var passwdtimer *time.Timer
	lstactivity = time.Now()
	isonlysecr := !isempty(key2)

	go func() {
		select {
		case <-stopticklogout:
			stopticklogout = make(chan struct{})
		default:
		}
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			select {
			case <-stopticklogout:
				return
			default:
				if time.Since(lstactivity) >= 5*time.Minute {
					fyne.Do(func() {
						logout()
					})
				}
			}
		}
	}()

	rtitle := widget.NewRichTextFromMarkdown("# выберите объект")
	rsitedescr := widget.NewLabel("")
	rsite := newclicklab("", func() {
		if int(seld) < len(vault) {
			clipb(vault[seld].site)
		}
		lstactivity = time.Now()
	})
	rsitecont := container.NewBorder(
		nil, nil,
		rsitedescr,
		rsite,
	)

	ruserndescr := widget.NewLabel("")
	rusern := newclicklab("", func() {
		if int(seld) < len(vault) {
			clipb(vault[seld].usern)
		}
		lstactivity = time.Now()
	})
	ruserncont := container.NewBorder(
		nil, nil,
		ruserndescr,
		rusern,
	)

	rpasswddescr := widget.NewLabel("")
	rpasswd := newclicklab("", func() { clipb("") })
	rpasswd = newclicklab("", func() {
		if int(seld) < len(vault) {
			clipbpasswd(vault[seld].chunk, vault[seld].issecr, &rpasswd.Label, &passwdtimer)
		}
		lstactivity = time.Now()
	})
	rpasswdcont := container.NewBorder(
		nil, nil,
		rpasswddescr,
		rpasswd,
	)

	rdatecdescr := widget.NewLabel("")
	rdatec := widget.NewLabel("")
	rdateccont := container.NewBorder(
		nil, nil,
		rdatecdescr,
		rdatec,
	)

	rdateedescr := widget.NewLabel("")
	rdatee := widget.NewLabel("")
	rdateecont := container.NewBorder(
		nil, nil,
		rdateedescr,
		rdatee,
	)

	detail := container.NewVBox(
		rtitle,
		rsitecont,
		ruserncont,
		rpasswdcont,
		rdateccont,
		rdateecont,
	)

	rcont := container.NewStack(detail)

	logoutb := widget.NewButton("", func() {
		close(stopticklogout)
		logout()
	})
	seticon(logoutb, "logout")

	secrb := widget.NewButton("", func() {})
	secrb = widget.NewButton("", func() {
		if isonlysecr {
			seticon(secrb, "secr")
		} else {
			seticon(secrb, "secr-chd")
		}
		isonlysecr = !isonlysecr
	})
	seticon(secrb, "secr-chd")

	favb := widget.NewButton("", func() {})
	favb = widget.NewButton("", func() {
		if seld == 65535 {
			return
		}
		vault[seld].isfav = !vault[seld].isfav
		if vault[seld].isfav {
			seticon(favb, "fav-chd")
		} else {
			seticon(favb, "fav")
		}

		passwdt := getpasswd(vault[seld].chunk, vault[seld].issecr)
		data := pack(vault[seld], passwdt)
		wipe(passwdt)
		encrdata := encr(data, key)
		wipe(data)
		if isempty(encrdata) {
			showerr("не удалось сделать объект избранным.")
			return
		}

		writechunk(vault[seld].chunk, encrdata, nil)

		lstactivity = time.Now()
	})
	seticon(favb, "fav")

	itemls := widget.NewList(
		func() int { return len(vault) },
		func() fyne.CanvasObject { return widget.NewLabel("Template") },
		func(i widget.ListItemID, obj fyne.CanvasObject) {
			text := vault[i].title
			if vault[i].usern != "" {
				text += " | " + vault[i].usern
			}
			obj.(*widget.Label).SetText(text)
		},
	)

	itemls.OnSelected = func(id widget.ListItemID) {
		lstactivity = time.Now()
		seld = uint16(id)
		if int(seld) >= len(vault) {
			showerr("ошибка в отображении списка.")
			return
		}

		rtitle.ParseMarkdown("# " + vault[seld].title)

		if vault[seld].site != "" {
			rsitedescr.SetText("сайт:")
			rsite.Text = vault[seld].site
			rsitecont.Show()
		} else {
			rsitecont.Hide()
		}

		if vault[seld].usern != "" {
			ruserndescr.SetText("логин:")
			rusern.Text = vault[seld].usern
			ruserncont.Show()
		} else {
			ruserncont.Hide()
		}

		rpasswddescr.SetText("пароль:")
		rpasswd.Text = "********"

		if vault[seld].datec != "" {
			rdatecdescr.SetText("дата создания:")
			rdatec.SetText(vault[seld].datec)
			rdateccont.Show()
		} else {
			rdateccont.Hide()
		}

		if vault[seld].datee != "" {
			rdateedescr.SetText("дата последнего изменения:")
			rdatee.SetText(vault[seld].datee)
			rdatee.Show()
		} else {
			rdatee.Hide()
		}
		if vault[seld].isfav {
			seticon(favb, "fav-chd")
		} else {
			seticon(favb, "fav")
		}

		rsite.Refresh()
		rusern.Refresh()
		rpasswd.Refresh()

		rcont.Objects = []fyne.CanvasObject{detail}
		rcont.Refresh()
	}

	searchent := widget.NewEntry()
	searchent.SetPlaceHolder("⌕ поиск")
	searchent.Wrapping = fyne.TextWrapOff
	searchent.Scroll = fyne.ScrollNone
	searchcont := container.NewGridWrap(fyne.NewSize(200, 30), searchent)

	// add object
	titleent, titlecont := newentry()
	titlecont = container.NewBorder(
		nil, nil,
		widget.NewLabel("название сервиса:"),
		titlecont,
	)
	siteent, sitecont := newentry()
	sitecont = container.NewBorder(
		nil, nil,
		widget.NewLabel("сайт:"),
		sitecont,
	)
	usernent, userncont := newentry()
	userncont = container.NewBorder(
		nil, nil,
		widget.NewLabel("юзернейм:"),
		userncont,
	)

	passwdent := widget.NewPasswordEntry()
	passwdent.Wrapping = fyne.TextWrapOff
	passwdent.Scroll = fyne.ScrollNone
	passwdcont := container.NewBorder(
		nil, nil,
		widget.NewLabel("пароль:"),
		container.NewGridWrap(fyne.NewSize(200, 30), passwdent),
	)

	doneaddb := widget.NewButton("готово", func() {
		newobj := lvault{
			title:  titleent.Text,
			site:   siteent.Text,
			usern:  usernent.Text,
			datec:  "",
			datee:  "",
			isfav:  false,
			issecr: false,
			chunk:  65535,
		}
		passwdt := []byte(passwdent.Text)

		flag := writeobj(newobj, passwdt, 65535)
		if !flag {
			wipe(passwdt)
			return
		}

		titleent.Text = ""
		siteent.Text = ""
		usernent.Text = ""
		passwdent.Text = ""

		seld = uint16(len(vault) - 1)
		itemls.Select(int(seld))
		itemls.Refresh()
		lstactivity = time.Now()
	})
	doneaddcont := container.NewCenter(
		container.NewGridWrap(
			fyne.NewSize(300, 40),
			doneaddb,
		),
	)

	addscr := container.NewVBox(
		widget.NewRichTextFromMarkdown("# добавление обьекта"),
		titlecont,
		sitecont,
		userncont,
		passwdcont,
		doneaddcont,
	)

	addb := widget.NewButton("", func() {
		titleent.Text = ""
		siteent.Text = ""
		usernent.Text = ""
		passwdent.Text = ""

		seticon(favb, "fav")
		seld = 65535
		itemls.UnselectAll()

		rcont.Objects = []fyne.CanvasObject{addscr}
		rcont.Refresh()
		lstactivity = time.Now()
	})
	seticon(addb, "add")

	// edit object
	doneeditb := widget.NewButton("готово", func() {
		if seld == 65535 {
			return
		}
		obj := lvault{
			title:  titleent.Text,
			site:   siteent.Text,
			usern:  usernent.Text,
			datec:  vault[seld].datec,
			datee:  "",
			isfav:  vault[seld].isfav,
			issecr: vault[seld].issecr,
			chunk:  vault[seld].chunk,
		}
		passwdt := []byte(passwdent.Text)

		flag := writeobj(obj, passwdt, seld)
		if !flag {
			wipe(passwdt)
			return
		}

		titleent.Text = ""
		siteent.Text = ""
		usernent.Text = ""
		passwdent.Text = ""

		itemls.UnselectAll()
		itemls.Select(int(seld))
		itemls.Refresh()

		rcont.Objects = []fyne.CanvasObject{detail}
		rcont.Refresh()
		lstactivity = time.Now()
	})
	doneeditcont := container.NewCenter(
		container.NewGridWrap(
			fyne.NewSize(300, 40),
			doneeditb,
		),
	)

	editscr := container.NewVBox(
		widget.NewRichTextFromMarkdown("# изменение обьекта"),
		titlecont,
		sitecont,
		userncont,
		passwdcont,
		doneeditcont,
	)

	editb := widget.NewButton("", func() {
		if seld == 65535 {
			return
		}
		rcont.Objects = []fyne.CanvasObject{editscr}

		titleent.Text = vault[seld].title
		siteent.Text = vault[seld].site
		usernent.Text = vault[seld].usern
		passwdent.Text = string(getpasswd(vault[seld].chunk, vault[seld].issecr))

		rcont.Refresh()
		lstactivity = time.Now()
	})
	seticon(editb, "edit")

	// move object
	moveb := widget.NewButton("", func() {
		if seld == 65535 {
			return
		}
		var oldchunk uint16 = vault[seld].chunk
		newobj := lvault{
			title:  vault[seld].title,
			site:   vault[seld].site,
			usern:  vault[seld].usern,
			datec:  vault[seld].datec,
			datee:  "",
			isfav:  vault[seld].isfav,
			issecr: !vault[seld].issecr,
			chunk:  65535,
		}

		passwd := getpasswd(vault[seld].chunk, vault[seld].issecr)
		flag := writeobj(newobj, passwd, seld)
		if !flag {
			wipe(passwd)
			return
		}

		delchunk(oldchunk)
		freechunks[oldchunk] = true
		freechunks[vault[seld].chunk] = false

		selv := "обычное"
		if vault[seld].issecr {
			selv = "секретное"
		}
		dialog.ShowInformation("", "обьект был перенесен в "+selv+" хранилище.", window)
	})
	seticon(moveb, "move")

	// share object
	shareb := widget.NewButton("", func() {

	})
	seticon(shareb, "share")

	// delete object
	delb := widget.NewButton("", func() {
		if seld == 65535 {
			return
		}
		showoverl("удалить объект("+vault[seld].title+")?", func(isconf bool) {
			if isconf {
				freechunks[vault[seld].chunk] = true
				delchunk(vault[seld].chunk)
				vault[seld] = vault[len(vault)-1]
				vault = vault[:len(vault)-1]

				seld = 65535
				itemls.Refresh()
				itemls.UnselectAll()
				lstactivity = time.Now()
			}
		})
	})
	seticon(delb, "del")

	// panel
	pbsize := fyne.NewSize(40, 30)
	panel := container.NewVBox()
	if isempty(key2) {
		panel = container.NewVBox(container.NewHBox(
			container.NewGridWrap(pbsize, logoutb),
			searchcont,
			container.NewGridWrap(pbsize, addb),
			container.NewGridWrap(pbsize, editb),
			container.NewGridWrap(pbsize, favb),
			container.NewGridWrap(pbsize, shareb),
			container.NewGridWrap(pbsize, delb),
		))
	} else {
		panel = container.NewVBox(container.NewHBox(
			container.NewGridWrap(pbsize, logoutb),
			container.NewGridWrap(pbsize, secrb),
			searchcont,
			container.NewGridWrap(pbsize, addb),
			container.NewGridWrap(pbsize, editb),
			container.NewGridWrap(pbsize, favb),
			container.NewGridWrap(pbsize, moveb),
			container.NewGridWrap(pbsize, shareb),
			container.NewGridWrap(pbsize, delb),
		))
	}

	split := container.NewHSplit(itemls, rcont)
	split.Offset = 0.35

	content := container.NewBorder(
		panel,
		nil,
		nil,
		nil,
		split,
	)

	window.SetContent(content)
}

func main() {
	_, err := os.Stat(pathapp)
	if err == nil {
		getsalt()
		auth(false)
	} else if errors.Is(err, os.ErrNotExist) {
		makesalt()
		auth(true)
	} else {
		showerrf("не удалось получить информацию о состоянии базы паролей.", err)
	}

	window.Resize(fyne.NewSize(645, 430))
	appl.Settings().SetTheme(theme.DefaultTheme())
	window.ShowAndRun()
}
