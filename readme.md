## lokyvault — кроссплатформенный менеджер паролей с правдоподобным отрицанием.

приложение реализовано на **go** с gui-интерфейсом **fyne** и предоставляет следующие функциональные возможности:

  \> **двойное хранилище: основное и секретное**, доступ к которым осуществляется по отдельным паролям(при входе в секретное нужны оба пароля), что позволяет разделять обычные и конфиденциальные данные.
  
  \> **шифрование aes-256-gcm** с получением ключа через **argon2id(5 итераций, 64 мб памяти, 4 потока)**, что повышает устойчивость к брутфорсу.
  
  \> аутентификация на основе пароля длиной **не менее 8 символов**, **обязательно содержащей буквы**(допускаются цифры, спецсимволы & все прочие unicode символы), **проходящей по стойкости** через функцию, что повышает защиту по сравнению с числовыми pin-кодами.

  \> реализован **panic пин**, при вводе которого хранилище блокируется до ручной разблокировки сохраненными данными.
  
  \> **возможен импорт и экспорт** существующего хранилища в формате .lvault, что позволяет удобно переносить базу паролей.

  \> **размер хранилища фиксирован — 30мб**. возможно записать **до 6999 обычных & 23699 секретных объектов**.

  \> можно быстро **передавать объекты через qr** человеку, не установившему lokyvault.
  
  \> **все ключи и пароли затираются в памяти** после использования, что повышает защиту от утечки данных при дампе оперативной памяти. также, буфер обмена с паролями очищается через 5 минут.
  
  \> используется **чанковая(1 чанк = 1 кб) архитектура базы паролей**, что позволяет **перемешивать основное и секретное хранилища**.
  
  \> **кроссплатформенная поддержка** Windows, macOS, Debian, Android & iOS.

![скриншот программы](./web/lvault-preview.png)

<p>
  <a href="https://lvault.nafantik.fun">
  <img src="https://img.shields.io/badge/website-lvault.nafantik.fun-3030FF?logo=safari&logoColor=white"
  alt="открыть lvault.nafantik.fun"></a>
  <br>

  <a href="https://github.com/lokyshka/lokyvault/releases/latest/download/lokyvault.exe">
  <img src="https://img.shields.io/badge/download-Windows-0078D6?logo=data:image/svg%2Bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0id2hpdGUiPjxwYXRoIGQ9Ik0wIDMuNDQ5IDkuNzUgMi4xdjkuNDUxSDB6TTEwLjk0OSAxLjk0OSAyNCAwdjExLjRIMTAuOTQ5ek0wIDEyLjZoOS43NXY5LjQ1MUwwIDIwLjY5OXpNMTAuOTQ5IDEyLjZIMjRWMjRsLTEyLjktMS44MDF6Ii8%2BPC9zdmc%2B"
  alt="скачать .exe для Windows"></a>
  <br>

  <a href="https://github.com/lokyshka/lokyvault/releases/latest/download/lokyvault.dmg">
  <img src="https://img.shields.io/badge/download-macOS-000000?logo=apple&logoColor=white"
  alt="скачать .dmg для macOS"></a>
  <br>

  <a href="https://github.com/lokyshka/lokyvault/releases/latest/download/lokyvault.deb">
  <img src="https://img.shields.io/badge/download-Debian-A81D33?logo=debian&logoColor=white"
  alt="скачать .deb для Debian"></a>
  <br>

  <a href="https://github.com/lokyshka/lokyvault/releases/latest/download/lokyvault.apk">
  <img src="https://img.shields.io/badge/download-Android-A4C639?logo=android&logoColor=white"
  alt="скачать .apk для Android"></a>
  <br>

  <a href="https://github.com/lokyshka/lokyvault/releases/latest/download/lokyvault.ipa">
  <img src="https://img.shields.io/badge/download-iOS-333333?logo=apple&logoColor=white"
  alt="скачать .ipa для iPhone"></a>
  <br>
</p>

lokyvault распространяется под лицензией [GNU General Public License v3.0 (GPLv3)](LICENSE).

[by lxkyshka <img src="https://images.weserv.nl/?url=github.com/lokyshka.png&mask=circle" width="20" height="20" align="center">](https://github.com/lokyshka)