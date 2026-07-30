# 🛡️ PortShield Scanner (Web UI & Asenkron Siber Keşif Laboratuvarı)

Python ve FastAPI ile yazılmış; yüksek hızlı asenkron port tarama, zafiyet analizi, subdomain/dizin tespiti, otomatik zamanlayıcı ve e-posta raporlama yeteneklerine sahip premium bir siber güvenlik ve keşif (reconnaissance) aracıdır.

---

## 🚀 Öne Çıkan Özellikler

- **Asenkron Tarama Motoru (`asyncio`):** Binlerce portu paralel ve eşzamanlı olarak saniyeler içinde tarar.
- **Canlı CVE ve SSL Analizi:** Açık web portlarındaki servis sürümlerini analiz eder, SSL sertifikalarının geçerlilik gün sayısını doğrular ve ilgili CVE zafiyet kodlarını canlı API entegrasyonuyla listeler.
- **Gelişmiş Keşif Modülleri:**
  * **Alt Alan Adı (Subdomain) Arama**
  * **Gizli Web Dizinleri Keşfi (Directory Buster)**
  * **Swagger & API Belgeleri Tespiti**
- **WAF ve Zayıf Şifre Denetimi:** Sunucu önündeki WAF (Web Application Firewall) varlığını tespit eder. FTP/SSH açık çıktığında zayıf şifreleri (brute force) test eder.
- **Otomatik Zamanlayıcı ve E-posta Raporlama:** Belirlenen sürelerde arka planda otomatik taramalar gerçekleştirir ve oluşturulan **PDF Raporlarını** doğrudan belirttiğiniz Gmail adresine otomatik olarak gönderir.
- **Premium Web Kontrol Paneli:** 
  * Karanlık / Aydınlık tema geçişi (Tercih hafızalı).
  * Bulgular tablosunda sayfa yenilenmeden çalışan **Canlı Arama** ve **Zafiyet Filtreleme** butonları.
  * Tarama esnasında çift tıklamayı önleyen canlı yükleme (spinner) efekti.

---

## 🛠️ Kurulum Adımları

1. **Depoyu bilgisayarınıza indirin:**
   ```bash
   git clone https://github.com/Muhammetbilbay/PortShield-Scanner.git
   cd PortShield-Scanner
   ```

2. **Bağımlılıkları yükleyin:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Kullanım (Çalıştırma)

FastAPI web sunucusunu ve arayüzünü başlatmak için PowerShell veya CMD terminalinizde şu komutları sırasıyla çalıştırın:

```powershell
# Proje klasörüne gidin
cd "C:\Users\Muhammet Bilbay\OneDrive\Desktop\PortShield-Scanner"

# Web arayüzünü başlatın
python -m uvicorn app:app --reload
```

Sunucu başladıktan sonra tarayıcınızdan şu adrese giderek aracı kullanabilirsiniz:
👉 **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

---

## 📧 Otomatik E-posta Zamanlayıcı Kurulumu

Zamanlanmış tarama sonuçlarının e-postanıza gelebilmesi için:
1. Google hesabınızda iki adımlı doğrulamayı açın.
2. Google Güvenlik ayarlarından **"Uygulama şifreleri (App passwords)"** aratarak 16 haneli bir şifre oluşturun.
3. Web arayüzündeki *"Otomatik Zamanlanmış Tarama Kur"* formuna bu şifreyi ve kendi Gmail adresinizi girerek zamanlayıcıyı başlatın.
