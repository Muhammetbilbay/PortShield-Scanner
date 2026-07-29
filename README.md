# PortShield Tarayıcı (PortShield Scanner)

Python ile yazılmış, yüksek performanslı ve çoklu iş parçacığı (multi-threaded) desteğine sahip bir TCP Port Tarayıcı ve Sancak Yakalayıcı (Banner Grabber). Güvenlik denetimleri ve sızma testleri sırasındaki keşif (reconnaissance) aşamaları için tasarlanmıştır.

## Özellikler

- **Çoklu İş Parçacıklı Tarama Motoru**: Python'un `threading` ve iş parçacığı güvenli (thread-safe) kuyruk yapılarını kullanarak binlerce portu saniyeler içinde tarar.
- **Sancak Yakalama (Banner Grabbing)**: Çalışan uygulamaları ve bunların sürümlerini tanımlamak için açık portlardaki servis imzalarını (başlıklar, karşılama mesajları) yakalamaya çalışır.
- **Akıllı Geri Çekilme (Fallback)**: Servisin hemen bir banner döndürmemesi durumunda, keşfedilen portları bilinen protokol veritabanıyla eşleştirir.
- **Özel Port Aralıkları**: Belirli port aralıklarını (örneğin `1-1000`) ve port listelerini (örneğin `21,22,80,443`) destekler.
- **Temiz CLI Arayüzü**: Kolay okunabilirlik için renkli terminal çıktıları kullanır.

---

## Nasıl Çalışır?

### Eşzamanlılık ve Performans
Sıralı olarak yapılan standart soket taramaları çok fazla zaman alır. Port başına `1.0` saniyelik bir zaman aşımı (timeout), 1.000 portun sıralı taranmasının **16 dakikadan fazla** süreceği anlamına gelir.
PortShield, iş yükünü özel iş parçacığı sayılarına (örneğin 100 thread) dağıtan bir işçi kuyruğu havuzu (worker queue pool) tasarımı uygular ve 1.000 port için tarama süresini **10 saniyenin altına** indirir.

### Sancak Yakalama (Banner Grabbing) Mantığı
PortShield, açık portları bulmanın ötesine geçerek servislerden sürüm bilgisi talep eder:
- SSH, FTP ve SMTP gibi protokoller için sunucu, bağlantı kurulur kurulmaz hemen bir karşılama mesajı (banner) gönderir.
- HTTP/HTTPS için ise tarayıcı, yanıt olarak bir web sunucusu imzası tetiklemek amacıyla standart bir istek (`HEAD / HTTP/1.1`) gönderir.

---

## Kurulum ve Kurulum Adımları

1. **Depoyu klonlayın:**
   ```bash
   git clone https://github.com/kullaniciadi/PortShield-Scanner.git
   cd PortShield-Scanner
   ```

2. **Gerekli paketleri yükleyin:**
   ```bash
   pip install -r requirements.txt
   ```

## Kullanım

Tarayıcıyı `python scanner.py` komutuyla ve özel parametrelerle çalıştırın:

```bash
# Bir alan adının varsayılan portlarını (1-1024) tarayın
python scanner.py -t scanme.nmap.org

# 150 iş parçacığı ve 0.5s zaman aşımı ile özel aralık tarayın
python scanner.py -t 192.168.1.1 -p 20-500 -w 150 --timeout 0.5

# Belirli portları tarayın
python scanner.py -t scanme.nmap.org -p 22,80,443
```
