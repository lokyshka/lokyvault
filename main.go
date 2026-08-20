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
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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

const logging bool = true

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

var appl = app.NewWithID("com.lokyvault.app")
var window = appl.NewWindow("lokyvault | менеджер паролей")

var pathapp string = getpathapp()

/* var easypins [70]string = [70]string{
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
} */

var chunks1 = make([]uint16, 7000-1)
var chunks2 = make([]uint16, 30700)
var seed, seed2 [2]uint64
var key, key2, salt []byte
var vault = make([]lvault, 0)

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
}

func importvault(isnew *bool) func() {
	return func() {
		path, err := zenity.SelectFile(
			zenity.Title("выберите файл хранилища паролей"),
			zenity.FileFilters{
				{Name: "файлы lokyvault (*.lvault)", Patterns: []string{"lvault", "*.lvault"}},
			},
		)

		if err != nil && !errors.Is(err, zenity.ErrCanceled) {
			showerr("не удалось импортировать выбранный файл.")
			return
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".lvault" {
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

	}
}

func loadchunk(chunk uint16, file *os.File, issecr bool, ispasswd bool) []byte {
	var isfav bool
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
		return nil
	}

	data := bytes.Split(text, []byte{0x1e})
	if len(data) != 7 {
		return nil
	}
	if ispasswd {
		return data[3]
	}
	wipe(data[3])
	if bytes.Equal(data[6], []byte{0x79}) {
		isfav = true
	}

	vault = append(vault, lvault{
		title:  string(data[0]),
		site:   string(data[1]),
		usern:  string(data[2]),
		datec:  string(data[4]),
		datee:  string(data[5]),
		isfav:  isfav,
		issecr: issecr,
		chunk:  chunk,
	})
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
	if bytes.Equal(key2, []byte{}) {
		return
	}
	for _, chunk := range chunks2 {
		loadchunk(chunk, file, true, false)
	}
}

func checkpin(pin []byte) bool {
	var isletter bool
	var r rune
	var size int
	if utf8.RuneCount(pin) < 6 {
		showerr("пин должен состоять из 6 символов(буквы обязательны, можно цифры и спецсимволы)!\nвозможно, у вас выбрана неверная раскладка клавиатуры.")
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
		textd = "придумайте пин длиной от 6 символов для шифрования хранилища паролей.\nбуквы обязательны, цифры и спецсимволы разрешены."
	} else {
		texth = "# хранилище защищено"
		textd = "введите пин(от 6 символов), чтобы снять защиту."
	}

	header := widget.NewRichTextFromMarkdown(texth)
	label := widget.NewLabelWithStyle(textd, fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	label.Wrapping = fyne.TextWrapWord

	letsgob := widget.NewButton("", func() { premainui(isnew) })
	letsgob.Hide()

	entry := widget.NewPasswordEntry()
	entrycont := container.NewGridWrap(fyne.NewSize(300, 40), entry)
	entry.SetPlaceHolder("введите пин")

	if isnew {
		var fstpin, fstpin2 []byte
		var fstdone bool
		expimpvault = widget.NewButton("импорт", importvault(&isnew))

		chunks1 = make([]uint16, 7000-1)
		chunks2 = make([]uint16, 30700)
		for i := range 30700 {
			chunks2[i] = uint16(i)
		}

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
		expimpvault = widget.NewButton("экспорт", exportvault())
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
	topleft := container.NewPadded(
		container.NewHBox(expimpvault),
	)

	content := container.NewStack(
		login,
		container.NewBorder(container.NewBorder(nil, nil, nil, topleft, nil), nil, nil, nil, nil),
	)
	window.SetContent(content)
}

func genkey(pin []byte, salt []byte) []byte {
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
		file, err := os.OpenFile(pathapp, os.O_WRONLY, 0666)
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

func encr(text []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию.", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		showerrf("ошибка подготовки данных к шифрованию 2.", err)
	}

	nlen := gcm.NonceSize() // 12bytes
	ohlen := gcm.Overhead() // 16bytes
	maxdatalen := 1024 - nlen - ohlen

	if len(text) > maxdatalen-2 {
		showerrf("переполнение ячейки данными.", nil)
	}

	nonce := make([]byte, nlen)
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

func decr(ciphert []byte, key []byte, nonce []byte) ([]byte, error) {
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

func (c *clicklab) Tapped(e *fyne.PointEvent) {
	if c.ontap != nil {
		c.ontap()
	}
}

func makeclicklab(text string, funct func()) *clicklab {
	lab := &clicklab{ontap: funct}
	lab.Text = text
	lab.ExtendBaseWidget(lab)
	return lab
}

func clipb(text string) {
	appl.Clipboard().SetContent(text)
	dialog.ShowInformation("", "данные были скопированы в буфер обмена.", window)
}

func clipbpasswd(chunk uint16, issecr bool, label *widget.Label) {
	passwd := loadchunk(chunk, nil, issecr, true)
	if label.Text == "пароль: ********" || label.Text == "" {
		label.Text = "пароль: " + string(passwd)
		label.Refresh()
	} else {
		appl.Clipboard().SetContent(string(passwd))
		dialog.ShowInformation("", "пароль был скопирован в буфер обмена.", window)
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
	const noseld = 65535
	var seld uint16 = noseld

	// start test
	vault = append(vault, lvault{
		title:  "nafshop",
		site:   "shop.nafantik.fun",
		usern:  "lxkyshka",
		datec:  "05.05.2021 15:31",
		datee:  "11.07.2026 17:01",
		isfav:  false,
		issecr: false,
		chunk:  419,
	})

	vault = append(vault, lvault{
		title:  "lumograph",
		site:   "lum.nafantik.fun",
		usern:  "nafantikxv",
		datec:  "19.07.2021 01:43",
		datee:  "20.07.2026 12:49",
		isfav:  false,
		issecr: false,
		chunk:  901,
	})
	// end test

	rtitle := widget.NewRichTextFromMarkdown("# выберите объект")
	rsite := makeclicklab("", func() {
		if int(seld) < len(vault) {
			clipb(vault[seld].site)
		}
	})
	rusern := makeclicklab("", func() {
		if int(seld) < len(vault) {
			clipb(vault[seld].usern)
		}
	})
	rpasswd := makeclicklab("", func() { clipb("") })
	rpasswd = makeclicklab("", func() {
		if int(seld) < len(vault) {
			clipbpasswd(vault[seld].chunk, vault[seld].issecr, &rpasswd.Label)
		}
	})
	rdatec := widget.NewLabel("")
	rdatee := widget.NewLabel("")

	itemls := widget.NewList(
		func() int { return len(vault) },
		func() fyne.CanvasObject { return widget.NewLabel("Template") },
		func(i widget.ListItemID, obj fyne.CanvasObject) {
			text := vault[i].title + " | " + vault[i].usern
			obj.(*widget.Label).SetText(text)
		},
	)

	detail := container.NewVBox(
		rtitle,
		rsite,
		rusern,
		rpasswd,
		rdatec,
		rdatee,
	)

	settings := container.NewVBox(
		widget.NewRichTextFromMarkdown("# настройки"),
		// widget.NewCheck("чек-поинт", func() {}),
	)

	rcont := container.NewStack(detail)

	itemls.OnSelected = func(id widget.ListItemID) {
		seld = uint16(id)
		if int(seld) >= len(vault) {
			showerr("ошибка в отображении списка.")
			return
		}

		rtitle.ParseMarkdown("# " + vault[seld].title)
		rsite.Text = "сайт: " + vault[seld].site
		rusern.Text = "логин: " + vault[seld].usern
		rpasswd.Text = "пароль: ********"
		rdatec.SetText("дата создания: " + vault[seld].datec)
		rdatee.SetText("дата последнего изменения:" + vault[seld].datee)

		rsite.Refresh()
		rusern.Refresh()
		rpasswd.Refresh()

		rcont.Objects = []fyne.CanvasObject{detail}
		rcont.Refresh()
	}

	settingsb := widget.NewButton("⚙ настройки", func() {
		itemls.UnselectAll()
		rcont.Objects = []fyne.CanvasObject{settings}
		rcont.Refresh()
	})

	downleft := container.NewPadded(settingsb)
	leftpanel := container.NewStack(
		itemls,
		container.NewBorder(nil, downleft, nil, nil, nil),
	)

	split := container.NewHSplit(leftpanel, rcont)
	split.Offset = 0.35
	window.SetContent(split)
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

	window.Resize(fyne.NewSize(600, 400))
	appl.Settings().SetTheme(theme.DefaultTheme())
	window.ShowAndRun()
}

/*

to-do in debugging :

[ ] 1. изменить showerrf() так, чтобы он останавливал выполнение кода.
[+] 2. передавать *os.File / nil в read-write-chunk().
[ ] 3. изменить структуру хранения данных по чанкам:
	проходить не абсолютно все чанки, а чанки до 1-ого мусорного.
	при удалении данных переносить последний чанк с полезными данными в удаляемый.
	добавить кнопку попытки восстановления обьектов.
[ ] 4. увеличить минимальную длину pin до 8символов.
[ ] 5. изменить формат запичи данных в чанк: писать длину значения, а после само значение.
[ ] 6. изменить тип passwd на []byte в работе с mainui().
[ ] 7. очищать пароль из буфера спустя определенное время.
[ ] 8. изменить заполнение базы шумом в makevault() — 30мб шума стоят дорого, особенно без аппаратного генератора.
[ ] 9. делать wipe() с чувствительными данными абсолютно везде.

*/
