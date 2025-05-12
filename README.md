# Windows Security Manager Pro

![Windows Security Manager Pro](https://raw.githubusercontent.com/slaweallx/WSMPro/refs/heads/main/wsmpro.png)
A powerful and user-friendly tool for managing Windows built-in security features with just one click. Maximize your Windows security without third-party antivirus software.

**Powered by Slaweally (Megabre.com)**

## 🔒 Features

- **One-Click Maximum Security**: Instantly optimize all Windows security settings with a single click
- **Simple Controls**: Easy-to-use interface for both beginners and advanced users
- **Windows Defender Management**: Enable/disable Windows Defender with one click
- **Firewall Control**: Manage Windows Firewall settings easily
- **Multilingual**: Available in English and Turkish
- **Advanced Settings**: Fine-tune individual security components for professional users
- **Firewall Port Management**: Open or close specific ports through a simple interface
- **Security Status Monitoring**: See your current security level at a glance

## 📋 Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or newer
- Administrator privileges

## 🚀 Installation & Running

1. Download the `Windows-Security-Manager-Pro.ps1` file
2. Right-click on the file and select "Run with PowerShell"
3. If you encounter an execution policy error, open PowerShell as Administrator and run this command first:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

4. Then navigate to the file location and run:

```powershell
.\Windows-Security-Manager-Pro.ps1
```

## 📘 Usage Guide

### Main Dashboard

The main dashboard provides quick access to essential security functions:

- **Windows Defender Panel**:
  - Click "Enable Defender" to turn on real-time protection
  - Click "Disable Defender" to turn off (not recommended)
  - Use "Quick Scan" to initiate a system security scan
  - Update virus definitions with "Update Virus Definitions"

- **Windows Firewall Panel**:
  - Click "Enable Firewall" to activate Windows Firewall
  - Click "Disable Firewall" to deactivate (not recommended)
  - Access Windows Security Center or Firewall Settings directly

- **Maximum Security**:
  - Click the large "Enable Maximum Security" button to optimize all security settings at once

### Security Status

At the top of the application, you'll see:
- Current security level (High, Medium, Low)
- Windows Defender status
- Windows Firewall status

These indicators change color based on your security settings (green for good, yellow for moderate, red for concerning).

### Firewall Tab

- Enable/disable specific network profiles (Domain, Private, Public)
- Configure inbound connection rules
- Manage firewall ports easily through the graphical interface

### Advanced Settings Tab

Fine-tune individual security components:
- Real-time Protection
- Behavior Monitoring
- Downloaded File Protection
- Network Attack Protection
- Automatic Updates
- SmartScreen Filter
- User Account Control (UAC)
- Data Execution Prevention (DEP)

### Language Switching

- Click the language button in the top-right corner to switch between English and Turkish

## 📋 License

[MIT License](LICENSE)

## 📧 Contact & Contribution

For questions, feedback, or contributions, please contact:
- Slaweally
- Website: [Megabre.com](https://megabre.com)

---

# Windows Güvenlik Yöneticisi Pro

![Windows Güvenlik Yöneticisi Pro](https://via.placeholder.com/800x400?text=Windows+G%C3%BCvenlik+Y%C3%B6neticisi+Pro)

Windows'un yerleşik güvenlik özelliklerini tek tıklamayla yönetmenizi sağlayan güçlü ve kullanıcı dostu bir araç. Üçüncü parti antivirüs yazılımlarına gerek kalmadan Windows güvenliğinizi maksimuma çıkarın.

**Powered by Slaweally (Megabre.com)**

## 🔒 Özellikler

- **Tek Tıkla Maksimum Güvenlik**: Tüm Windows güvenlik ayarlarını tek tıklamayla optimize edin
- **Basit Kontroller**: Hem yeni başlayanlar hem de ileri düzey kullanıcılar için kolay kullanımlı arayüz
- **Windows Defender Yönetimi**: Windows Defender'ı tek tıklamayla etkinleştirin/devre dışı bırakın
- **Güvenlik Duvarı Kontrolü**: Windows Güvenlik Duvarı ayarlarını kolayca yönetin
- **Çok Dilli**: İngilizce ve Türkçe dil seçenekleri
- **Gelişmiş Ayarlar**: Profesyonel kullanıcılar için ayrı güvenlik bileşenlerini ince ayarla
- **Güvenlik Duvarı Port Yönetimi**: Basit bir arayüz ile belirli portları açın veya kapatın
- **Güvenlik Durumu İzleme**: Mevcut güvenlik seviyenizi bir bakışta görün

## 📋 Gereksinimler

- Windows 10 veya Windows 11
- PowerShell 5.1 veya daha yeni
- Yönetici hakları

## 🚀 Kurulum ve Çalıştırma

1. `Windows-Security-Manager-Pro.ps1` dosyasını indirin
2. Dosyaya sağ tıklayın ve "PowerShell ile Çalıştır" seçeneğini seçin
3. Çalıştırma politikası hatası alırsanız, PowerShell'i Yönetici olarak açın ve önce bu komutu çalıştırın:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

4. Ardından dosya konumuna gidin ve şunu çalıştırın:

```powershell
.\Windows-Security-Manager-Pro.ps1
```

## 📘 Kullanım Kılavuzu

### Ana Panel

Ana panel, temel güvenlik işlevlerine hızlı erişim sağlar:

- **Windows Defender Paneli**:
  - Gerçek zamanlı korumayı açmak için "Defender'ı Etkinleştir" düğmesine tıklayın
  - Kapatmak için "Defender'ı Devre Dışı Bırak" düğmesine tıklayın (önerilmez)
  - Sistem güvenlik taraması başlatmak için "Hızlı Tarama Başlat" düğmesini kullanın
  - "Virüs İmzalarını Güncelle" ile virüs tanımlarını güncelleyin

- **Windows Güvenlik Duvarı Paneli**:
  - Windows Güvenlik Duvarı'nı etkinleştirmek için "Güvenlik Duvarını Etkinleştir" düğmesine tıklayın
  - Devre dışı bırakmak için "Güvenlik Duvarını Devre Dışı Bırak" düğmesine tıklayın (önerilmez)
  - Windows Güvenlik Merkezi'ne veya Güvenlik Duvarı Ayarlarına doğrudan erişin

- **Maksimum Güvenlik**:
  - Tüm güvenlik ayarlarını bir kerede optimize etmek için büyük "Maksimum Güvenliği Etkinleştir" düğmesine tıklayın

### Güvenlik Durumu

Uygulamanın üst kısmında şunları göreceksiniz:
- Mevcut güvenlik seviyesi (Yüksek, Orta, Düşük)
- Windows Defender durumu
- Windows Güvenlik Duvarı durumu

Bu göstergeler, güvenlik ayarlarınıza bağlı olarak renk değiştirir (iyi için yeşil, orta için sarı, endişe verici için kırmızı).

### Güvenlik Duvarı Sekmesi

- Belirli ağ profillerini (Etki Alanı, Özel, Genel) etkinleştirin/devre dışı bırakın
- Gelen bağlantı kurallarını yapılandırın
- Güvenlik duvarı portlarını grafiksel arayüz üzerinden kolayca yönetin

### Gelişmiş Ayarlar Sekmesi

Ayrı güvenlik bileşenlerini ince ayarlayın:
- Gerçek Zamanlı Koruma
- Davranış İzleme
- İndirilen Dosya Koruması
- Ağ Saldırısı Koruması
- Otomatik Güncellemeler
- SmartScreen Filtresi
- Kullanıcı Hesabı Denetimi (UAC)
- Veri Yürütme Engelleme (DEP)

### Dil Değiştirme

- İngilizce ve Türkçe arasında geçiş yapmak için sağ üst köşedeki dil düğmesine tıklayın

## 📋 Lisans

[MIT Lisansı](LICENSE)

## 📧 İletişim ve Katkı

Sorular, geri bildirimler veya katkılar için lütfen iletişime geçin:
- Slaweally -> Sys@rootali.net
- Web sitesi: [Megabre.com](https://megabre.com)
