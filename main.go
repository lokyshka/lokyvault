package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"errors"
	"image"
	_ "image/png"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	zxcvbn "github.com/nbutton23/zxcvbn-go"
	"github.com/ncruces/zenity"
	qr "github.com/yeqown/go-qrcode/v2"
	qrst "github.com/yeqown/go-qrcode/writer/standard"
	qrshapes "github.com/yeqown/go-qrcode/writer/standard/shapes"
	"golang.org/x/crypto/argon2"
)

func showerrf(descr string) {
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

func showconfirm(text string, result func(bool)) {
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
			if idx != 65535 {
				break
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

	window.SetTitle("lokyvault | менеджер паролей")
	if appclosed {
		return
	}
	if stopticker != nil {
		stopticker()
		stopticker = nil
	}

	_, err := os.Stat(pathapp)
	if err == nil {
		getsalt()
		auth(false)
	} else if errors.Is(err, os.ErrNotExist) {
		makesalt()
		auth(true)
	} else {
		showerrf("не удалось получить информацию о состоянии базы паролей.")
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
		window.Resize(fyne.NewSize(645, 430))
		window.ShowAndRun()
		showerrf("ошибка получения домашней папки.")
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		os.Stdout = devnull
		os.Stderr = devnull
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(homedir, "AppData", "Local", "lokyvault", "passwdb.lvault")
	case "darwin":
		return filepath.Join(homedir, "Library", "Application Support", "lokyvault", "passwdb.lvault")
	case "ios":
		ismobile = true
		return filepath.Join(homedir, "Documents", "lokyvault", "passwdb.lvault")
	case "android":
		ismobile = true
		return filepath.Join(homedir, "files", "lokyvault", "passwdb.lvault")
	default:
		return filepath.Join(homedir, ".local", "share", "lokyvault", "passwdb.lvault")
	}
}

func askpath(issave bool) string {
	var path, titlet, errtxt string
	var err error
	ext := []string{".lvault"}

	if issave {
		titlet = "выберите, куда сохранить файл хранилища паролей"
		errtxt = "не удалось экспортировать выбранный файл."
	} else {
		titlet = "выберите файл хранилища паролей"
		errtxt = "не удалось импортировать выбранный файл."
	}

	if ismobile {
		var filedialog *dialog.FileDialog

		if issave {
			filedialog = dialog.NewFileSave(func(reader fyne.URIWriteCloser, err error) {
				if err != nil {
					showerr(errtxt)
					return
				}
				if reader == nil {
					return
				}

				path = reader.URI().Path()
			}, window)
		} else {
			filedialog = dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if err != nil {
					showerr(errtxt)
					return
				}
				if reader == nil {
					return
				}

				path = reader.URI().Path()
			}, window)
		}

		filedialog.SetTitleText(titlet)
		filedialog.SetFilter(
			storage.NewExtensionFileFilter(ext),
		)
		if issave {
			filedialog.SetFileName("passwdb.lvault")
		}
		filedialog.Show()
	} else {
		ztitle := zenity.Title(titlet)
		zfilter := zenity.FileFilter{
			Name:     "файлы lokyvault (*.lvault)",
			Patterns: ext,
		}
		if issave {
			path, err = zenity.SelectFileSave(
				ztitle,
				zenity.Filename("passwdb.lvault"),
				zfilter,
				zenity.ConfirmOverwrite(),
			)
		} else {
			path, err = zenity.SelectFile(
				ztitle,
				zfilter,
			)
		}

		if errors.Is(err, zenity.ErrCanceled) {
			return ""
		}

		if err != nil {
			showerr(errtxt)
		}
	}
	return path
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
type writecloser struct {
	*bytes.Buffer
}

const version string = "v1.2-beta"

var appl = app.NewWithID("com.lokyvault.app")
var window = appl.NewWindow("lokyvault | менеджер паролей")
var stopticker context.CancelFunc
var ismobile, appclosed bool
var pathapp string = getpathapp()

var vault []lvault
var filtered []uint16

var chunks1 = make([]uint16, 7000-1)
var chunks2 = make([]uint16, 30700)
var freechunks = make([]bool, 30700)

var seed, seed2 [2]uint64
var key, key2, salt []byte
var searchq string
var lstactivity time.Time
var lstactmutex sync.RWMutex

func makevault() {
	err := os.MkdirAll(filepath.Dir(pathapp), 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		showerrf("ошибка создания папки для хранения данных.")
		return
	}

	file, err := os.OpenFile(pathapp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		showerrf("ошибка создания хранилища.")
		return
	}
	defer func() {
		err := file.Close()
		if err != nil {
			showerrf("ошибка создания хранилища.")
			return
		}
	}()

	noise := make([]byte, 30*1024*1024-16)
	_, err = crand.Read(noise)
	if err != nil {
		showerrf("ошибка создания хранилища.")
		return
	}

	data := make([]byte, 30*1024*1024)
	copy(data, noise)
	copy(data[30*1024*1024-16:], salt)

	n, err := file.Write(data)
	if err != nil || n < len(data) {
		showerrf("ошибка создания хранилища.")
		return
	}

	towrite := encr([]byte("lokyvault passwdb"), key)

	rnd1 := mrand.New(mrand.NewPCG(seed[0], seed[1]))
	randnum := rnd1.Uint32N(30700)
	writechunk(uint16(randnum), towrite, file)

	if !isempty(key2) {
		towrite = encr([]byte("lokyvault passwdb"), key2)

		rnd2 := mrand.New(mrand.NewPCG(seed2[0], seed2[1]))
		randnum = rnd2.Uint32N(23700)
		writechunk(chunks2[randnum], towrite, file)
	}

	chunks2[randnum] = chunks2[len(chunks2)-1]
	chunks2 = chunks2[:len(chunks2)-1]
}

func importvault(isnew *bool) {
	path := askpath(false)
	if path == "" {
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

func exportvault() {
	path := askpath(true)
	if path == "" {
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
		showerrf("ошибка чтения объекта.")
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
	var isletter, isupper bool
	var r rune
	var size int

	if utf8.RuneCount(pin) < 8 {
		showerr("длина пина должна быть от 8 символов(буквы обязательны, можно цифры и спецсимволы)!\nвозможно, у вас выбрана неверная раскладка клавиатуры.")
		return false
	}

	for i := 0; i < len(pin); {
		r, size = utf8.DecodeRune(pin[i:])
		if (r == utf8.RuneError && size == 1) || unicode.IsSpace(r) {
			showerr("вы ввели недопустимые символы!")
			return false
		}
		if unicode.IsLetter(r) {
			isletter = true
		}
		if unicode.IsUpper(r) {
			isupper = true
		}
		i += size
	}

	if !isletter {
		showerr("в пине должна быть как минимум 1 буква!")
		return false
	}

	if !isupper {
		showerr("в пине должна быть хотя бы 1 заглавная буква!")
		return false
	}

	result := zxcvbn.PasswordStrength(string(pin), nil)
	if result.Score < 3 {
		showerr("слишком слабый пароль!")
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
		expimpvault = widget.NewButton("  импорт  ", func() { importvault(&isnew) })

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
				showerrf("слишком много неудачных попыток. перезапустите приложение.")
				return
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
		expimpvault = widget.NewButton("  экспорт  ", func() { exportvault() })
		entry.OnSubmitted = func(s string) {
			pinbad = []byte(entry.Text)
			entry.SetText("")
			cnt++
			if cnt > 3 {
				showerrf("слишком много неудачных попыток.")
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
		showerrf("ошибка алгоритма для обработки базы данных паролей.")
		return
	}
}

func getsalt() {
	file, err := os.OpenFile(pathapp, os.O_RDONLY, 0666)
	if err != nil {
		showerrf("не удалось открыть базу паролей для получения метаданных.")
		return
	}
	defer file.Close()

	salt = make([]byte, 16)
	offset := int64(30*1024*1024 - 16)
	_, err = file.ReadAt(salt, offset)
	if err != nil {
		showerrf("ошибка в чтении дополнительных данных базы паролей.")
		return
	}
}

func readchunk(chnk uint16, file *os.File) ([]byte, []byte) {
	var err error
	if file == nil {
		file, err = os.OpenFile(pathapp, os.O_RDONLY, 0666)
		if err != nil {
			showerr("ошибка чтения хранилища.")
			return nil, nil
		}
		defer file.Close()
	}

	data := make([]byte, 1024)
	offset := int64(chnk) * 1024
	_, err = file.ReadAt(data, offset)
	if err != nil {
		showerr("ошибка чтения хранилища.")
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
			showerr("ошибка записи хранилища.")
			return
		}
		defer func() {
			err := file.Close()
			if err != nil {
				showerr("ошибка записи хранилища.")
				return
			}
		}()
	}

	offset := int64(chnk) * 1024
	_, err = file.WriteAt(data, offset)
	if err != nil {
		showerr("ошибка записи хранилища.")
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
		showerrf("ошибка подготовки данных к шифрованию.")
		return nil
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию.")
		return nil
	}

	maxdatalen := 1024 - 12 - gcm.Overhead()

	if len(text) > maxdatalen-2 {
		showerrf("слишком большой ввод!")
		return nil
	}

	nonce := make([]byte, 12)
	_, err = crand.Read(nonce)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию.")
		return nil
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
		showerrf("ошибка подготовки данных к шифрованию.")
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию 2.")
		return nil, err
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
	var lencur, length uint32
	var data lvault
	var passwd []byte
	var datalen uint32 = uint32(len(btext))
	var err1, err2, err3, err4, err5 bool

	getvaule := func() (string, bool) {
		if length+2 > datalen {
			showerr("произошла ошибка при разбивке чанка!")
			return "", true
		}
		lencur = uint32(binary.BigEndian.Uint16(btext[length:length+2])) + 2
		if length+lencur > datalen {
			showerr("произошла ошибка при разбивке чанка!")
			return "", true
		}
		text := string(btext[length+2 : length+lencur])
		text = strings.ReplaceAll(text, "\x00", "")
		length += lencur
		return text, false
	}

	data.title, err1 = getvaule()
	data.site, err2 = getvaule()
	data.usern, err3 = getvaule()
	data.datec, err4 = getvaule()
	data.datee, err5 = getvaule()

	if err1 || err2 || err3 || err4 || err5 {
		return lvault{}, nil
	}

	if length+1 > datalen {
		showerr("произошла ошибка при разбивке чанка!")
		return lvault{}, nil
	}
	if btext[length] == 1 {
		data.isfav = true
	}
	length++

	if length+2 > datalen {
		showerr("произошла ошибка при разбивке чанка!")
		return lvault{}, nil
	}
	lencur = uint32(binary.BigEndian.Uint16(btext[length:length+2])) + 2

	if length+lencur > datalen {
		showerr("произошла ошибка при разбивке чанка!")
		return lvault{}, nil
	}
	if ispasswd {
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
		wipe(btext[length+2 : length+lencur])
		passwd = nil
	}

	data.chunk = chunknum
	data.issecr = issecr

	return data, passwd
}

func writeobj(data lvault, passwdt []byte, seld uint16) bool {
	var isnew bool
	timenow := time.Now().Format("02.01.2006 15:04")
	if data.chunk == 65535 {
		data.chunk = freech(data.issecr)
		if data.chunk == 65535 {
			showerr("слишком много записанных паролей / внутренная ошибка !")
			return false
		}
	}
	if data.datec == "" {
		data.datec = timenow
		isnew = true
	}
	if data.datee == "" {
		data.datee = timenow
	} else if seld == 65535 {
		showerr("ошибка записи обьекта!")
		return false
	}

	if data.title == "" || isempty(passwdt) {
		wipe(passwdt)
		showerr("поля заглавия и пароля обязательны!")
		return false
	}

	length := len(data.title) + len(data.site) +
		len(data.usern) + len(passwdt) +
		len(data.datec) + len(data.datee)
	if length > 996 {
		wipe(passwdt)
		showerr("слишком длинные данные!")
		return false
	}

	if isnew || seld == 65535 {
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
	freechunks[data.chunk] = false
	return true
}

func sortvault() {
	sort.SliceStable(vault, func(i, j int) bool {
		if vault[i].isfav != vault[j].isfav {
			return vault[i].isfav
		}
		return strings.ToLower(vault[i].title) < strings.ToLower(vault[j].title)
	})
}

func filterv(isonlysecr bool) {
	filtered = filtered[:0]
	for i, item := range vault {
		if item.issecr == isonlysecr {
			if searchq == "" ||
				strings.Contains(strings.ToLower(item.title), searchq) ||
				strings.Contains(strings.ToLower(item.site), searchq) ||
				strings.Contains(strings.ToLower(item.usern), searchq) {

				filtered = append(filtered, uint16(i))
			}
		}
	}
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

func (_ writecloser) Close() error {
	return nil
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
	case "back":
		text = " ⬅ "
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

func confclipb(data []byte, timer **time.Timer) {
	appl.Clipboard().SetContent(string(data))
	dialog.ShowInformation("", "данные были скопированы в буфер обмена.\nчерез 5 минут буфер обмена будет очищен.", window)
	if *timer != nil {
		(*timer).Stop()
	}
	*timer = time.AfterFunc(5*time.Minute, func() {
		appl.Clipboard().SetContent("")
	})
}

func clipbpasswd(chunk uint16, issecr bool, label *widget.Label, timer **time.Timer) {
	passwd := getpasswd(chunk, issecr)
	if label.Text == "********" || label.Text == "" {
		label.SetText(string(passwd))
		wipe(passwd)
	} else {
		confclipb(passwd, timer)
		wipe(passwd)
	}
}

func activupd() {
	lstactmutex.Lock()
	lstactivity = time.Now()
	lstactmutex.Unlock()
}

func genqr(data lvault, passwd []byte) *fyne.StaticResource {
	var text string

	if data.title != "" {
		text = "сервис: " + data.title + "\n"
	}
	if data.site != "" {
		text += "сайт: " + data.site + "\n"
	}
	if data.usern != "" {
		text += "юзернейм: " + data.usern + "\n"
	}
	if !isempty(passwd) {
		text += "пароль: "
	}

	qrcode, err := qr.NewWith(
		text+string(passwd),
		qr.WithErrorCorrectionLevel(qr.ErrorCorrectionHighest),
	)
	wipe(passwd)
	if err != nil {
		showerr("не удалось сгенерировать qr-код.")
		return nil
	}

	backg := qrst.WithBgColorRGBHex("#FFFFFF")
	foreg := qrst.WithFgColorRGBHex("#000000")
	nameicon := "lvault-monoch-light.png"

	if fyne.CurrentApp().Settings().ThemeVariant() == theme.VariantDark {
		backg = qrst.WithBgColorRGBHex("#000000")
		foreg = qrst.WithFgColorRGBHex("#FFFFFF")
		nameicon = "lvault-monoch-dark.png"
	}

	liquidshape := qrshapes.Assemble(
		qrshapes.RoundedFinder(), // скругляет 3 угловых квадрата
		qrshapes.LiquidBlock(),   // соединяет соседние блоки в жидкие капли
	)

	options := []qrst.ImageOption{
		qrst.WithCustomShape(liquidshape), // жидкая форма точек и скругление
		qrst.WithQRWidth(20),              // размер ячейки
		qrst.WithBorderWidth(1, 1, 1, 1),  // отступы по краям
		backg,                             // цвет фона
		foreg,                             // цвет точек
	}

	path := filepath.Join("assets", nameicon)
	iconb, err := icons.ReadFile(path)
	if err == nil {
		img, _, err := image.Decode(bytes.NewReader(iconb))
		if err == nil {
			options = append(options, qrst.WithLogoImage(img)) // иконка
		}
	}

	var buf bytes.Buffer
	w := qrst.NewWithWriter(writecloser{&buf}, options...)

	if err := qrcode.Save(w); err != nil {
		showerr("не удалось сгенерировать qr-код.")
		return nil
	}

	qrimg := fyne.NewStaticResource("qr-code", buf.Bytes())
	return qrimg
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
	var isonlysecr bool
	activupd()
	if !isempty(key2) {
		window.SetTitle("lokyvault | cекретное хранилище")
		isonlysecr = true
	}
	sortvault()
	filterv(isonlysecr)

	if stopticker != nil {
		stopticker()
	}
	ctx, cancel := context.WithCancel(context.Background())
	stopticker = cancel

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lstactmutex.RLock()
				istimeout := time.Since(lstactivity) >= 5*time.Minute
				lstactmutex.RUnlock()
				if istimeout {
					fyne.Do(func() {
						logout()
					})
					return
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
		activupd()
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
		activupd()
	})
	ruserncont := container.NewBorder(
		nil, nil,
		ruserndescr,
		rusern,
	)

	rpasswddescr := widget.NewLabel("")
	rpasswd := newclicklab("", func() { clipb("") })
	rpasswd.ontap = func() {
		if int(seld) < len(vault) {
			clipbpasswd(vault[seld].chunk, vault[seld].issecr, &rpasswd.Label, &passwdtimer)
		}
		activupd()
	}
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

	mbackb := widget.NewButton("", func() {})
	seticon(mbackb, "back")
	if !ismobile {
		mbackb.Hide()
	}

	detail := container.NewBorder(
		nil,
		mbackb,
		nil,
		nil,
		container.NewVBox(
			rtitle,
			rsitecont,
			ruserncont,
			rpasswdcont,
			rdateccont,
			rdateecont,
		),
	)

	rcont := container.NewStack(detail)
	center := container.NewStack()
	leftside := container.NewBorder(nil, nil, nil, nil)

	cleardetail := func() {
		seld = 65535
		rtitle.ParseMarkdown("# выберите объект")
		rsitecont.Hide()
		ruserncont.Hide()
		rpasswddescr.SetText("")
		rpasswd.Text = ""
		rpasswd.Refresh()
		rdateccont.Hide()
		rdateecont.Hide()
		rcont.Objects = []fyne.CanvasObject{detail}
		rcont.Refresh()
	}
	favb := widget.NewButton("", func() {})

	itemls := widget.NewList(
		func() int {
			return len(filtered)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Template")
		},
		func(i widget.ListItemID, obj fyne.CanvasObject) {
			if i >= len(filtered) {
				return
			}
			idx := filtered[i]
			text := vault[idx].title
			if vault[idx].usern != "" {
				text += " | " + vault[idx].usern
			}
			obj.(*widget.Label).SetText(text)
		},
	)

	itemls.OnSelected = func(id widget.ListItemID) {
		seld = filtered[id]
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
			rdateecont.Show()
		} else {
			rdateecont.Hide()
		}
		if vault[seld].isfav {
			seticon(favb, "fav-chd")
		} else {
			seticon(favb, "fav")
		}

		rsite.Refresh()
		rusern.Refresh()
		rpasswd.Refresh()
		activupd()

		if !ismobile {
			rcont.Objects = []fyne.CanvasObject{detail}
			rcont.Refresh()
		} else {
			center.Objects = []fyne.CanvasObject{detail}
			center.Refresh()
		}
	}

	// logout
	logoutb := widget.NewButton("", func() {
		logout()
	})
	seticon(logoutb, "logout")

	// secret objects only
	secrb := widget.NewButton("", func() {})
	secrb.OnTapped = func() {
		if ismobile {
			center.Objects = []fyne.CanvasObject{leftside}
		}
		if isonlysecr {
			seticon(secrb, "secr")
			window.SetTitle("lokyvault | менеджер паролей")
		} else {
			seticon(secrb, "secr-chd")
			window.SetTitle("lokyvault | cекретное хранилище")
		}

		isonlysecr = !isonlysecr
		filterv(isonlysecr)

		itemls.Refresh()
		itemls.UnselectAll()
		seticon(favb, "fav")
		cleardetail()
		activupd()
	}
	seticon(secrb, "secr-chd")

	// search objects
	searchent := widget.NewEntry()
	searchent.SetPlaceHolder("")
	searchent.Wrapping = fyne.TextWrapOff
	searchent.Scroll = fyne.ScrollNone
	icon := loadicon("search")
	if icon == nil {
		searchent.SetPlaceHolder("⌕ поиск")
	} else {
		searchent.SetIcon(icon)
		searchent.SetPlaceHolder("поиск")
	}

	searchent.OnChanged = func(text string) {
		searchq = text
		filterv(isonlysecr)
		itemls.Refresh()
		activupd()
	}
	searchpccont := container.NewGridWrap(
		fyne.NewSize(200, 30),
		searchent,
	)
	searchmbcont := container.NewVBox(searchent)

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
			issecr: isonlysecr,
			chunk:  65535,
		}
		passwdt := []byte(passwdent.Text)

		flag := writeobj(newobj, passwdt, 65535)
		if !flag {
			wipe(passwdt)
			return
		}

		titleent.SetText("")
		siteent.SetText("")
		usernent.SetText("")
		passwdent.SetText("")

		chunknum := vault[len(vault)-1].chunk
		sortvault()

		for i, item := range vault {
			if item.chunk == chunknum {
				seld = uint16(i)
				break
			}
		}
		filterv(isonlysecr)
		itemls.Refresh()

		for lsidx, vidx := range filtered {
			if vidx == seld {
				itemls.Select(lsidx)
				break
			}
		}
		activupd()
	})
	doneaddcont := container.NewCenter(
		container.NewGridWrap(
			fyne.NewSize(300, 40),
			doneaddb,
		),
	)

	addscr := container.NewBorder(
		nil,
		mbackb,
		nil,
		nil,
		container.NewVBox(
			widget.NewRichTextFromMarkdown("# добавление обьекта"),
			titlecont,
			sitecont,
			userncont,
			passwdcont,
			doneaddcont,
		),
	)

	addb := widget.NewButton("", func() {
		titleent.SetText("")
		siteent.SetText("")
		usernent.SetText("")
		passwdent.SetText("")

		seticon(favb, "fav")
		seld = 65535
		itemls.UnselectAll()

		if !ismobile {
			if rcont.Objects[0] == addscr {
				rcont.Objects = []fyne.CanvasObject{detail}
			} else {
				rcont.Objects = []fyne.CanvasObject{addscr}
			}
			rcont.Refresh()
		} else {
			if center.Objects[0] == addscr {
				center.Objects = []fyne.CanvasObject{leftside}
			} else {
				center.Objects = []fyne.CanvasObject{addscr}
			}
			center.Refresh()
		}
		activupd()
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

		titleent.SetText("")
		siteent.SetText("")
		usernent.SetText("")
		passwdent.SetText("")

		sortvault()
		filterv(isonlysecr)
		itemls.Refresh()

		for i, item := range vault {
			if item.chunk == obj.chunk {
				seld = uint16(i)
				break
			}
		}
		itemls.UnselectAll()

		for lsidx, vidx := range filtered {
			if vidx == seld {
				itemls.Select(lsidx)
				break
			}
		}

		rcont.Objects = []fyne.CanvasObject{detail}
		rcont.Refresh()
		activupd()
	})
	doneeditcont := container.NewCenter(
		container.NewGridWrap(
			fyne.NewSize(300, 40),
			doneeditb,
		),
	)

	editscr := container.NewBorder(
		nil,
		mbackb,
		nil,
		nil,
		container.NewVBox(
			widget.NewRichTextFromMarkdown("# изменение обьекта"),
			titlecont,
			sitecont,
			userncont,
			passwdcont,
			doneeditcont,
		),
	)

	editb := widget.NewButton("", func() {
		if seld == 65535 {
			return
		}

		if !ismobile {
			if rcont.Objects[0] == editscr {
				rcont.Objects = []fyne.CanvasObject{detail}
			} else {
				rcont.Objects = []fyne.CanvasObject{editscr}
			}
			rcont.Refresh()
		} else {
			if center.Objects[0] == editscr {
				center.Objects = []fyne.CanvasObject{detail}
			} else {
				center.Objects = []fyne.CanvasObject{editscr}
			}
			center.Refresh()
		}

		titleent.SetText(vault[seld].title)
		siteent.SetText(vault[seld].site)
		usernent.SetText(vault[seld].usern)
		passwdent.SetText(string(getpasswd(vault[seld].chunk, vault[seld].issecr)))

		rcont.Refresh()
		activupd()
	})
	seticon(editb, "edit")

	// fav object
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
		var encrdata []byte
		if vault[seld].issecr {
			encrdata = encr(data, key2)
		} else {
			encrdata = encr(data, key)
		}
		wipe(data)
		if isempty(encrdata) {
			showerr("не удалось сделать объект избранным.")
			return
		}

		writechunk(vault[seld].chunk, encrdata, nil)

		chunknum := vault[seld].chunk
		sortvault()
		filterv(isonlysecr)

		for i, item := range vault {
			if item.chunk == chunknum {
				seld = uint16(i)
				break
			}
		}
		itemls.UnselectAll()

		for lsidx, vidx := range filtered {
			if vidx == seld {
				itemls.Select(lsidx)
				break
			}
		}
		activupd()
	})
	seticon(favb, "fav")

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

		if ismobile {
			center.Objects = []fyne.CanvasObject{leftside}
			seticon(favb, "fav")
		}

		selv := "обычное"
		if vault[seld].issecr {
			selv = "секретное"
		}
		dialog.ShowInformation("", "обьект был перенесен в "+selv+" хранилище.", window)

		filterv(isonlysecr)
		itemls.Refresh()
		itemls.UnselectAll()
		cleardetail()
		activupd()
	})
	seticon(moveb, "move")

	// share object
	titlechk := widget.NewCheck("название сервиса", nil)
	sitechk := widget.NewCheck("сайт", nil)
	usernchk := widget.NewCheck("юзернейм", nil)
	passwdchk := widget.NewCheck("пароль", nil)

	showqrb := widget.NewButton("qr-код", func() {
		var passwdt []byte

		obj := lvault{
			title: "",
			site:  "",
			usern: "",
		}

		if seld == 65535 {
			return
		}

		if !(titlechk.Checked || sitechk.Checked || usernchk.Checked || passwdchk.Checked) {
			showerr("выберите хотя бы один пункт!")
			return
		}

		if titlechk.Checked {
			obj.title = vault[seld].title
		}
		if sitechk.Checked {
			obj.site = vault[seld].site
		}
		if usernchk.Checked {
			obj.usern = vault[seld].usern
		}
		if passwdchk.Checked {
			passwdt = getpasswd(vault[seld].chunk, vault[seld].issecr)
		}

		qrcode := genqr(obj, passwdt)
		wipe(passwdt)
		if qrcode == nil {
			return
		}

		qrc := widget.NewIcon(qrcode)
		qrcont := container.NewGridWrap(
			fyne.NewSize(250, 250),
			qrc,
		)

		qrDialog := dialog.NewCustom("qr-код", "закрыть", qrcont, window)
		qrDialog.Show()
	})

	copyb := widget.NewButton("скопировать", func() {
		var text string
		var passwdt []byte

		if seld == 65535 {
			return
		}

		if !(titlechk.Checked || sitechk.Checked || usernchk.Checked || passwdchk.Checked) {
			showerr("выберите хотя бы один пункт!")
			return
		}

		if titlechk.Checked {
			text = "название сервиса: " + vault[seld].title + "\n"
		}
		if sitechk.Checked && vault[seld].site != "" {
			text += "сайт: " + vault[seld].site + "\n"
		}
		if usernchk.Checked && vault[seld].usern != "" {
			text += "юзернейм: " + vault[seld].usern + "\n"
		}
		if passwdchk.Checked {
			text += "пароль: "
			passwdt = getpasswd(vault[seld].chunk, vault[seld].issecr)
		}

		result := append([]byte(text), passwdt...)
		if len(passwdt) > 0 {
			wipe(passwdt)
		}

		confclipb(result, &passwdtimer)
		wipe(result)
	})
	copyb.Importance = widget.MediumImportance

	sharebtnscont := container.NewCenter(
		container.NewHBox(
			container.NewGridWrap(
				fyne.NewSize(150, 40),
				copyb,
			),
			container.NewGridWrap(
				fyne.NewSize(150, 40),
				showqrb,
			),
		),
	)

	sharescr := container.NewBorder(
		nil,
		mbackb,
		nil,
		nil,
		container.NewVBox(
			widget.NewRichTextFromMarkdown("# поделиться объектом"),
			widget.NewRichTextFromMarkdown("## данные для передачи:"),
			titlechk,
			sitechk,
			usernchk,
			passwdchk,
			sharebtnscont,
		),
	)

	shareb := widget.NewButton("", func() {
		if seld == 65535 {
			return
		}

		titlechk.SetChecked(true)
		sitechk.SetChecked(true)
		usernchk.SetChecked(true)
		passwdchk.SetChecked(false)

		if !ismobile {
			if rcont.Objects[0] == sharescr {
				rcont.Objects = []fyne.CanvasObject{detail}
			} else {
				rcont.Objects = []fyne.CanvasObject{sharescr}
			}
			rcont.Refresh()
		} else {
			if center.Objects[0] == sharescr {
				center.Objects = []fyne.CanvasObject{detail}
			} else {
				center.Objects = []fyne.CanvasObject{sharescr}
			}
			center.Refresh()
		}

	})
	seticon(shareb, "share")

	// delete object
	delb := widget.NewButton("", func() {
		if seld == 65535 {
			return
		}
		showconfirm("удалить объект("+vault[seld].title+")?", func(isconf bool) {
			if isconf {
				if seld == 65535 {
					showerr("ошибка удаления объета!")
					return
				}
				freechunks[vault[seld].chunk] = true
				delchunk(vault[seld].chunk)
				vault[seld] = vault[len(vault)-1]
				vault = vault[:len(vault)-1]

				if ismobile {
					center.Objects = []fyne.CanvasObject{leftside}
					seticon(favb, "fav")
				}

				sortvault()
				filterv(isonlysecr)
				itemls.Refresh()
				itemls.UnselectAll()
				cleardetail()
			}
			activupd()
		})
	})
	seticon(delb, "del")

	// back button
	mbackb.OnTapped = func() {
		if center.Objects[0] == detail || center.Objects[0] == addscr {
			seld = 65535
			itemls.UnselectAll()
			itemls.Refresh()
			seticon(favb, "fav")
			center.Objects = []fyne.CanvasObject{leftside}
		} else {
			center.Objects = []fyne.CanvasObject{detail}
		}
	}

	// panel
	pbsize := fyne.NewSize(40, 30)
	panel := container.NewVBox()
	secrcont := container.NewGridWrap(pbsize, secrb)
	movecont := container.NewGridWrap(pbsize, moveb)
	if isempty(key2) {
		secrcont.Hide()
		secrb.Hide()
		movecont.Hide()
		moveb.Hide()
	}
	if ismobile {
		var mbtns []fyne.CanvasObject
		mbtns = append(mbtns, logoutb)
		if !isempty(key2) {
			mbtns = append(mbtns, secrb)
		}
		mbtns = append(mbtns, addb, editb, favb)
		if !isempty(key2) {
			mbtns = append(mbtns, moveb)
		}
		mbtns = append(mbtns, shareb, delb)

		panel = container.NewVBox(
			container.NewGridWithColumns(len(mbtns), mbtns...),
		)
	} else {
		searchmbcont.Hide()
		panel = container.NewVBox(
			container.NewHBox(
				container.NewGridWrap(pbsize, logoutb),
				secrcont,
				searchpccont,
				container.NewGridWrap(pbsize, addb),
				container.NewGridWrap(pbsize, editb),
				container.NewGridWrap(pbsize, favb),
				movecont,
				container.NewGridWrap(pbsize, shareb),
				container.NewGridWrap(pbsize, delb),
			),
		)
	}

	// finishing
	leftside = container.NewBorder(
		nil,
		searchmbcont,
		nil,
		nil,
		itemls,
	)
	center.Objects = []fyne.CanvasObject{leftside}

	split := container.NewHSplit(itemls, rcont)
	split.Offset = 0.35

	content := container.NewBorder(nil, nil, nil, nil)
	if !ismobile {
		content = container.NewBorder(
			panel,
			nil,
			nil,
			nil,
			split,
		)
	} else {
		content = container.NewBorder(
			panel,
			nil,
			nil,
			nil,
			center,
		)
	}

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
		showerrf("не удалось получить информацию о состоянии базы паролей.")
	}

	appl.Settings().SetTheme(theme.DefaultTheme())
	window.Resize(fyne.NewSize(645, 430))
	window.SetOnClosed(func() {
		appclosed = true
		logout()
	})
	window.ShowAndRun()
}
