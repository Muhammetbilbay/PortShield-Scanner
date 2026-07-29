import socket
import sys
import time
import argparse
import json
import ipaddress
from threading import Thread, Lock
from queue import Queue

# Renkli çıktı için colorama kütüphanesini içe aktarmayı dene, kurulu değilse yedek mekanizmaya geç
try:
    from colorama import init, Fore, Style
    init()
    GREEN = Fore.GREEN
    RED = Fore.RED
    YELLOW = Fore.YELLOW
    BLUE = Fore.BLUE
    RESET = Style.RESET_ALL
except ImportError:
    GREEN = RED = YELLOW = BLUE = RESET = ""

# Konsol çıktıları için iş parçacığı güvenliği (Thread safety) kilidi
print_lock = Lock()

# Banner alınamadığında kullanılacak yaygın port-servis eşleştirmeleri
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy"
}

def get_banner(s, port):
    """
    Açık soketten banner (servis kimlik bilgisi) almayı dener.
    """
    try:
        # Bazı servisler ilk bağlantıda kendileri mesaj gönderir (örn: SSH, FTP, SMTP). Hemen okumayı deneriz.
        s.settimeout(1.5)
        
        # HTTP/HTTPS ise web sunucusu başlık bilgisini tetiklemek için bir istek göndermemiz gerekir.
        if port in [80, 8080]:
            s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        elif port == 443:
            # Basit HTTPS isteği (tam SSL el sıkışması olmadan, başarısız olabilir ama denemeye değer)
            s.send(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner:
            # Banner bilgisini tek satıra sığacak şekilde temizle
            return banner.replace('\r', '').replace('\n', ' | ')
    except Exception:
        pass
    
    # Banner alınamazsa bilinen port listesindeki servis adını döndür
    return COMMON_PORTS.get(port, "Bilinmeyen Servis")

def scan_port(target_ip, port, timeout):
    """
    Hedef IP üzerindeki tek bir portu tarar. Geriye (port, acik_mi, banner) döndürür.
    """
    try:
        # Soket nesnesi oluştur
        # AF_INET = IPv4, SOCK_STREAM = TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        
        # Bağlantıyı dene
        result = s.connect_ex((target_ip, port))
        
        if result == 0:
            # Port açık, banner almaya çalış
            banner = get_banner(s, port)
            s.close()
            return port, True, banner
        else:
            s.close()
            return port, False, None
    except Exception:
        return port, False, None

def analyze_banner(banner):
    """
    Banner bilgisini analiz eder ve bilinen eski veya riskli servislere dair uyarılar üretir.
    """
    warnings = []
    if not banner or banner == "Bilinmeyen Servis":
        return warnings
        
    banner_lower = banner.lower()
    
    # OpenSSH Analizi
    if "openssh" in banner_lower:
        try:
            version_str = banner_lower.split("openssh_")[1].split()[0]
            # Temel versiyon sayılarını al
            version_num = float(''.join([c for c in version_str if c.isdigit() or c == '.'])[:3])
            if version_num < 8.5:
                warnings.append(f"Zafiyet Riski: Eski OpenSSH sürümü ({version_str}). Bilinen CVE zafiyetleri içerebilir. Güncelleme önerilir.")
        except Exception:
            pass
            
    # Apache Analizi
    elif "apache" in banner_lower:
        try:
            version_str = banner_lower.split("apache/")[1].split()[0]
            version_parts = [int(p) for p in ''.join([c for c in version_str if c.isdigit() or c == '.']).split('.') if p]
            if len(version_parts) >= 3 and version_parts[0] == 2 and version_parts[1] == 4 and version_parts[2] < 49:
                warnings.append(f"Zafiyet Riski: Eski Apache HTTPD sürümü ({version_str}). CVE-2021-41773 ve CVE-2021-42013 zafiyetlerine karşı korumasız olabilir.")
        except Exception:
            pass

    # Nginx Analizi
    elif "nginx" in banner_lower:
        if "1.18" in banner_lower or "1.14" in banner_lower or "1.16" in banner_lower:
            warnings.append("Bilgi: Potansiyel eski Nginx sürümü tespit edildi.")

    # FTP / vsFTPd
    elif "vsftpd" in banner_lower:
        if "2.3.4" in banner_lower:
            warnings.append("KRİTİK HATA: vsFTPd 2.3.4 Arka Kapı (Backdoor) sürümü olabilir! (CVE-2011-2523)")

    # SMB
    elif banner == "SMB":
        warnings.append("Bilgi: SMB servisi açık. MS17-010 (EternalBlue) zafiyetine karşı yama durumunu kontrol edin.")
        
    return warnings


def worker(queue, timeout, open_ports, delay):
    """
    Kuyruktan (IP, port) ikililerini çekip tarayan işçi (worker) iş parçacığı.
    """
    while not queue.empty():
        try:
            target_ip, port = queue.get_nowait()
        except Exception:
            break
            
        # İstekler arası gecikme (milisaniye -> saniye)
        if delay > 0:
            time.sleep(delay / 1000.0)
            
        port, is_open, banner = scan_port(target_ip, port, timeout)
        
        if is_open:
            warnings = analyze_banner(banner)
            open_ports.append((target_ip, port, banner, warnings))
            with print_lock:
                print(f"[{GREEN}*{RESET}] {target_ip:<15} -> Port {BLUE}{port:<5}{RESET} -> {GREEN}AÇIK{RESET} | Servis: {YELLOW}{banner}{RESET}")
                for w in warnings:
                    print(f"    [{RED}!{RESET}] {RED}{w}{RESET}")
                
        queue.task_done()

def parse_ports(port_arg):
    """
    Port parametresini çözümler. Aralık (örn: 20-80) ve virgülle ayrılmış liste (örn: 22,80,443) destekler.
    """
    ports = []
    try:
        if '-' in port_arg:
            start, end = map(int, port_arg.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_arg:
            ports = [int(p.strip()) for p in port_arg.split(',')]
        else:
            ports = [int(port_arg)]
    except ValueError:
        print(f"[{RED}!{RESET}] Hata: Geçersiz port formatı. Örn: '80', '20-100' veya '22,80,443'")
        sys.exit(1)
    return ports

def parse_targets(target_arg):
    """
    Hedef parametresini çözümler. Tek IP, alan adı, CIDR (örn: 192.168.1.0/24) 
    veya IP aralığı (örn: 192.168.1.1-192.168.1.10) destekler.
    Geriye bir IP listesi döndürür.
    """
    targets = []
    try:
        # Virgülle ayrılmış liste desteği
        if ',' in target_arg:
            parts = [p.strip() for p in target_arg.split(',')]
            for part in parts:
                targets.extend(parse_targets(part))
        # CIDR desteği (örn: 192.168.1.0/24)
        elif '/' in target_arg:
            net = ipaddress.ip_network(target_arg, strict=False)
            if net.num_addresses > 2:
                targets.extend([str(ip) for ip in net.hosts()])
            else:
                targets.extend([str(ip) for ip in net])
        # IP Aralığı desteği (örn: 192.168.1.1-10 veya 192.168.1.1-192.168.1.10)
        elif '-' in target_arg and not target_arg.replace('-', '').isalpha():
            start_str, end_str = target_arg.split('-')
            start_str = start_str.strip()
            end_str = end_str.strip()
            
            if '.' not in end_str:
                base_ip = '.'.join(start_str.split('.')[:-1])
                end_str = f"{base_ip}.{end_str}"
                
            start_ip = ipaddress.ip_address(start_str)
            end_ip = ipaddress.ip_address(end_str)
            
            curr = start_ip
            while curr <= end_ip:
                targets.append(str(curr))
                curr += 1
        else:
            # Tekil IP veya Alan Adı
            try:
                ip = socket.gethostbyname(target_arg)
                targets.append(ip)
            except socket.gaierror:
                print(f"[{RED}!{RESET}] Hata: '{target_arg}' alan adı veya IP adresi çözümlenemedi.")
    except Exception as e:
        print(f"[{RED}!{RESET}] Hata (Hedef Çözümleme): {e}")
        sys.exit(1)
        
    seen = set()
    return [x for x in targets if not (x in seen or seen.add(x))]

def save_results(file_path, targets, open_ports, duration):
    """
    Tarama sonuçlarını uzantısına göre (JSON veya TXT/düz metin) dosyaya kaydeder.
    """
    try:
        if file_path.endswith('.json'):
            data = {
                "targets": targets,
                "scan_date": time.strftime('%Y-%m-%d %H:%M:%S'),
                "duration_seconds": round(duration, 2),
                "open_ports_count": len(open_ports),
                "open_ports": [{"ip": ip, "port": port, "banner": banner, "warnings": warnings} for ip, port, banner, warnings in open_ports]
            }
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        else:
            # Varsayılan olarak TXT formatında kaydet
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("-" * 60 + "\n")
                f.write(f" PortShield Tarama Raporu - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("-" * 60 + "\n")
                f.write(f" Hedef(ler)    : {', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}\n")
                f.write(f" Süre          : {duration:.2f} saniye\n")
                f.write(f" Açık Portlar  : {len(open_ports)} adet\n")
                f.write("-" * 60 + "\n")
                for ip, port, banner, warnings in open_ports:
                    f.write(f" Hedef: {ip:<15} | Port {port:<5} | Servis: {banner}\n")
                    for w in warnings:
                        f.write(f"    [!] UYARI: {w}\n")
                f.write("-" * 60 + "\n")
        print(f"[{GREEN}*{RESET}] Sonuçlar başarıyla kaydedildi: {BLUE}{file_path}{RESET}")
    except Exception as e:
        print(f"[{RED}!{RESET}] Sonuçlar kaydedilirken hata oluştu: {e}")

def main():
    parser = argparse.ArgumentParser(description="PortShield: Hızlı Çoklu İş Parçacıklı Port Tarayıcı ve Banner Yakalayıcı")
    parser.add_argument("-t", "--target", required=True, help="Hedef makine (IP veya alan adı)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port aralığı (örn: 20-100) veya virgülle ayrılmış liste (varsayılan: 1-1024)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Çalışacak iş parçacığı (thread) sayısı (varsayılan: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Soket bağlantı zaman aşımı süresi (saniye) (varsayılan: 1.0)")
    parser.add_argument("-o", "--output", help="Tarama sonuçlarının kaydedileceği dosya yolu (örn: sonuc.json veya sonuc.txt)")
    parser.add_argument("--delay", type=int, default=0, help="Her istek arasındaki gecikme süresi (milisaniye cinsinden, varsayılan: 0)")
    
    args = parser.parse_args()
    
    target_arg = args.target
    port_range_str = args.ports
    thread_count = args.workers
    timeout = args.timeout

    # Hedefleri çözümle
    print(f"[{BLUE}i{RESET}] Hedef(ler) çözümleniyor: {target_arg}...")
    targets = parse_targets(target_arg)
    
    if not targets:
        print(f"[{RED}!{RESET}] Hata: Taranacak geçerli bir hedef bulunamadı.")
        sys.exit(1)

    ports_to_scan = parse_ports(port_range_str)
    
    print("-" * 60)
    print(f" {GREEN}PortShield Port Tarayıcı & Banner Yakalayıcı{RESET}")
    print("-" * 60)
    print(f" Hedef Sayısı  : {len(targets)} cihaz ({', '.join(targets[:3])}{'...' if len(targets) > 3 else ''})")
    print(f" Taranacak Port: {port_range_str} ({len(ports_to_scan)} port/cihaz)")
    print(f" Thread Sayısı : {thread_count}")
    print(f" Zaman Aşımı   : {timeout}s")
    print(f" Başlangıç     : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    start_time = time.time()
    
    # Kuyruk yapısını oluştur ve (IP, port) ikililerini ekle
    queue = Queue()
    total_scans = 0
    for ip in targets:
        for port in ports_to_scan:
            queue.put((ip, port))
            total_scans += 1
        
    open_ports = []
    threads = []
    
    # İş parçacıklarını başlat
    num_threads = min(thread_count, total_scans)
    for _ in range(num_threads):
        t = Thread(target=worker, args=(queue, timeout, open_ports, args.delay))
        t.daemon = True
        t.start()
        threads.append(t)
        
    # Tüm işlemlerin bitmesini bekle
    for t in threads:
        t.join()
        
    duration = time.time() - start_time
    
    print("-" * 60)
    print(f" Tarama {duration:.2f} saniyede tamamlandı.")
    print(f" Toplam {len(open_ports)} adet açık port bulundu.")
    print("-" * 60)

    if args.output:
        save_results(args.output, targets, open_ports, duration)

if __name__ == "__main__":
    main()
