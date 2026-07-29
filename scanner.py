import socket
import sys
import time
import argparse
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

def worker(queue, target_ip, timeout, open_ports):
    """
    Kuyruktan portları çekip tarayan işçi (worker) iş parçacığı.
    """
    while not queue.empty():
        try:
            port = queue.get_nowait()
        except Exception:
            break
            
        port, is_open, banner = scan_port(target_ip, port, timeout)
        
        if is_open:
            open_ports.append((port, banner))
            with print_lock:
                print(f"[{GREEN}*{RESET}] Port {BLUE}{port:<5}{RESET} -> {GREEN}AÇIK{RESET} | Servis: {YELLOW}{banner}{RESET}")
                
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

def main():
    parser = argparse.ArgumentParser(description="PortShield: Hızlı Çoklu İş Parçacıklı Port Tarayıcı ve Banner Yakalayıcı")
    parser.add_argument("-t", "--target", required=True, help="Hedef makine (IP veya alan adı)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port aralığı (örn: 20-100) veya virgülle ayrılmış liste (varsayılan: 1-1024)")
    parser.add_argument("-w", "--workers", type=int, default=100, help="Çalışacak iş parçacığı (thread) sayısı (varsayılan: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Soket bağlantı zaman aşımı süresi (saniye) (varsayılan: 1.0)")
    
    args = parser.parse_args()
    
    target_host = args.target
    port_range_str = args.ports
    thread_count = args.workers
    timeout = args.timeout

    # Hedef alan adını IP adresine çöz çözümle
    try:
        print(f"[{BLUE}i{RESET}] Hedef çözümleniyor: {target_host}...")
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[{RED}!{RESET}] Hata: '{target_host}' alan adı çözümlenemedi.")
        sys.exit(1)

    ports_to_scan = parse_ports(port_range_str)
    
    print("-" * 60)
    print(f" {GREEN}PortShield Port Tarayıcı & Banner Yakalayıcı{RESET}")
    print("-" * 60)
    print(f" Hedef Adres   : {target_host} ({target_ip})")
    print(f" Taranacak Port: {port_range_str} ({len(ports_to_scan)} port)")
    print(f" Thread Sayısı : {thread_count}")
    print(f" Zaman Aşımı   : {timeout}s")
    print(f" Başlangıç     : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    start_time = time.time()
    
    # Kuyruk yapısını oluştur ve portları ekle
    queue = Queue()
    for port in ports_to_scan:
        queue.put(port)
        
    open_ports = []
    threads = []
    
    # İş parçacıklarını başlat
    # Port sayısı thread sayısından azsa sadece port sayısı kadar thread başlat
    num_threads = min(thread_count, len(ports_to_scan))
    for _ in range(num_threads):
        t = Thread(target=worker, args=(queue, target_ip, timeout, open_ports))
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

if __name__ == "__main__":
    main()
