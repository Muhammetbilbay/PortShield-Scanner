import socket
import sys
import time
import argparse
import json
import ipaddress
import asyncio
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

# En popüler port listeleri
TOP_PORTS = {
    10: [21, 22, 23, 25, 53, 80, 110, 443, 3389, 8080],
    50: [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1080, 1433, 1434, 1521, 1723,
        2049, 3128, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000, 9100, 27017, 6379, 1194, 8081, 8888, 9090, 5000,
        2121, 2222, 3000, 5901, 5902, 6001, 8008, 8082, 8083
    ],
    100: [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 139, 143, 161, 162, 179, 389,
        443, 445, 465, 514, 515, 540, 587, 636, 993, 995, 1080, 1433, 1434, 1521, 1723, 2049, 3128, 3306, 3389,
        5432, 5900, 5901, 6379, 8000, 8080, 8443, 9000, 9090, 9100, 27017, 1194, 3000, 5000, 8081, 8888, 5902,
        6001, 8008, 8082, 8083, 7000, 7001, 7002, 9200, 9300, 5672, 15672, 27018, 27019, 11211, 4567, 5555, 6000,
        6443, 8085, 8086, 8088, 8090, 8181, 8500, 8880, 9001, 9002, 9042, 9411, 9999, 10000, 1522, 26379, 50000,
        50070, 60000, 60010
    ]
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

def scan_udp_port(target_ip, port, timeout):
    """
    Hedef IP üzerindeki tek bir UDP portunu tarar.
    Geriye (port, acik_mi, banner) döndürür.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(b"", (target_ip, port))
        data, addr = s.recvfrom(1024)
        s.close()
        return port, True, "UDP Servisi (Yanıt Alındı)"
    except socket.timeout:
        s.close()
        # UDP'de timeout olması portun açık ya da filtreli olduğunu gösterir
        return port, True, "Açık | Filtrelenmiş (UDP)"
    except (ConnectionRefusedError, ConnectionResetError):
        s.close()
        return port, False, None
    except Exception:
        s.close()
        return port, False, None

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

async def get_banner_async(reader, writer, port):
    """
    Asenkron soket üzerinden banner almaya çalışır.
    """
    try:
        if port in [80, 8080]:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
        elif port == 443:
            writer.write(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            await writer.drain()
            
        data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
        banner = data.decode('utf-8', errors='ignore').strip()
        if banner:
            return banner.replace('\r', '').replace('\n', ' | ')
    except Exception:
        pass
    return COMMON_PORTS.get(port, "Bilinmeyen Servis")

async def scan_port_async(target_ip, port, timeout):
    """
    Hedef IP üzerindeki tek bir portu asenkron olarak tarar.
    """
    try:
        conn = asyncio.open_connection(target_ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        banner = await get_banner_async(reader, writer, port)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True, banner
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


def worker(queue, timeout, open_ports, delay, scan_mode):
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
            
        if scan_mode == "UDP":
            port, is_open, banner = scan_udp_port(target_ip, port, timeout)
        else:
            port, is_open, banner = scan_port(target_ip, port, timeout)
        
        if is_open:
            warnings = analyze_banner(banner)
            open_ports.append((target_ip, port, banner, warnings))
            with print_lock:
                print(f"[{GREEN}*{RESET}] {target_ip:<15} -> Port {BLUE}{port:<5}{RESET} -> {GREEN}AÇIK{RESET} | Servis: {YELLOW}{banner}{RESET}")
                for w in warnings:
                    print(f"    [{RED}!{RESET}] {RED}{w}{RESET}")
                
        queue.task_done()

async def scan_task(sem, target_ip, port, timeout, delay, scan_mode, open_ports):
    """
    Asenkron tarama görevini yürütür ve sınırlandırıcı semaphore'u uygular.
    """
    async with sem:
        if delay > 0:
            await asyncio.sleep(delay / 1000.0)
            
        if scan_mode == "UDP":
            port, is_open, banner = await asyncio.to_thread(scan_udp_port, target_ip, port, timeout)
        else:
            port, is_open, banner = await scan_port_async(target_ip, port, timeout)
            
        if is_open:
            warnings = analyze_banner(banner)
            open_ports.append((target_ip, port, banner, warnings))
            with print_lock:
                print(f"[{GREEN}*{RESET}] {target_ip:<15} -> Port {BLUE}{port:<5}{RESET} -> {GREEN}AÇIK{RESET} | Servis: {YELLOW}{banner}{RESET}")
                for w in warnings:
                    print(f"    [{RED}!{RESET}] {RED}{w}{RESET}")

async def async_scan_manager(targets, ports, timeout, delay, scan_mode, open_ports, max_workers):
    """
    Tüm asenkron tarama görevlerini koordine eder.
    """
    sem = asyncio.Semaphore(max_workers)
    tasks = []
    for ip in targets:
        for port in ports:
            tasks.append(scan_task(sem, ip, port, timeout, delay, scan_mode, open_ports))
    await asyncio.gather(*tasks)


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
    Tarama sonuçlarını uzantısına göre (JSON, HTML veya TXT/düz metin) dosyaya kaydeder.
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
        elif file_path.endswith('.html'):
            html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PortShield Tarama Raporu</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: rgba(30, 41, 59, 0.7);
            --border-color: rgba(255, 255, 255, 0.1);
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-green: #10b981;
            --accent-blue: #3b82f6;
            --accent-red: #ef4444;
            --accent-yellow: #f59e0b;
        }}
        body {{
            background-color: var(--bg-color);
            color: var(--text-primary);
            font-family: 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 40px 20px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .container {{
            max-width: 1000px;
            width: 100%;
        }}
        .header {{
            text-align: center;
            margin-bottom: 40px;
        }}
        .header h1 {{
            background: linear-gradient(135deg, #3b82f6, #10b981);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size: 2.5rem;
            margin: 0;
        }}
        .header p {{
            color: var(--text-secondary);
            margin: 10px 0 0 0;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        .stat-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            backdrop-filter: blur(10px);
        }}
        .stat-card h3 {{
            margin: 0;
            color: var(--text-secondary);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .stat-card p {{
            margin: 10px 0 0 0;
            font-size: 1.8rem;
            font-weight: bold;
            color: var(--accent-blue);
        }}
        .stat-card.green p {{ color: var(--accent-green); }}
        .stat-card.yellow p {{ color: var(--accent-yellow); }}
        .table-card {{
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            backdrop-filter: blur(10px);
        }}
        .table-card h2 {{
            margin-top: 0;
            margin-bottom: 20px;
            font-size: 1.3rem;
            border-left: 4px solid var(--accent-green);
            padding-left: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}
        th, td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.9rem;
        }}
        tr:hover {{
            background: rgba(255, 255, 255, 0.02);
        }}
        .port-badge {{
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            padding: 4px 8px;
            border-radius: 6px;
            font-weight: 600;
            font-family: monospace;
        }}
        .status-badge {{
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.85rem;
            font-weight: 500;
        }}
        .warning-list {{
            margin: 8px 0 0 0;
            padding: 0;
            list-style: none;
        }}
        .warning-item {{
            color: #fca5a5;
            background: rgba(239, 68, 68, 0.1);
            border-left: 3px solid var(--accent-red);
            padding: 6px 12px;
            border-radius: 4px;
            margin-top: 6px;
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PortShield Tarama Raporu</h1>
            <p>Güvenlik Denetimi ve Sürüm Analiz Raporu</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>Hedef Cihaz Sayısı</h3>
                <p>{len(targets)}</p>
            </div>
            <div class="stat-card green">
                <h3>Bulunan Açık Portlar</h3>
                <p>{len(open_ports)}</p>
            </div>
            <div class="stat-card">
                <h3>Tarama Süresi</h3>
                <p>{duration:.2f}s</p>
            </div>
            <div class="stat-card yellow">
                <h3>Tarih</h3>
                <p style="font-size: 1.1rem; line-height: 2.2rem;">{time.strftime('%Y-%m-%d %H:%M')}</p>
            </div>
        </div>

        <div class="table-card">
            <h2>Bulunan Açık Portlar ve Servis Detayları</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hedef IP</th>
                        <th>Port</th>
                        <th>Durum</th>
                        <th>Servis / Banner</th>
                    </tr>
                </thead>
                <tbody>
"""
            for ip, port, banner, warnings in open_ports:
                warning_html = ""
                if warnings:
                    warning_html = '<ul class="warning-list">' + ''.join([f'<li class="warning-item">{w}</li>' for w in warnings]) + '</ul>'
                html_content += f"""
                    <tr>
                        <td>{ip}</td>
                        <td><span class="port-badge">{port}</span></td>
                        <td><span class="status-badge">AÇIK</span></td>
                        <td>
                            <strong>{banner}</strong>
                            {warning_html}
                        </td>
                    </tr>
"""
            html_content += """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
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
    parser.add_argument("--top-ports", type=int, choices=[10, 50, 100], help="En yaygın X portu tarar (seçenekler: 10, 50, 100)")
    parser.add_argument("--udp", action="store_true", help="UDP taraması yapar (Varsayılan: TCP)")
    
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

    if args.top_ports:
        ports_to_scan = TOP_PORTS[args.top_ports]
        port_range_str = f"Top {args.top_ports} Ports"
    else:
        ports_to_scan = parse_ports(port_range_str)
    
    scan_mode = "UDP" if args.udp else "TCP"

    print("-" * 60)
    print(f" {GREEN}PortShield Port Tarayıcı & Banner Yakalayıcı{RESET}")
    print("-" * 60)
    print(f" Tarama Modu   : {scan_mode}")
    print(f" Hedef Sayısı  : {len(targets)} cihaz ({', '.join(targets[:3])}{'...' if len(targets) > 3 else ''})")
    print(f" Taranacak Port: {port_range_str} ({len(ports_to_scan)} port/cihaz)")
    print(f" Thread Sayısı : {thread_count}")
    print(f" Zaman Aşımı   : {timeout}s")
    print(f" Başlangıç     : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 60)

    start_time = time.time()
    open_ports = []
    
    # Asenkron tarama motorunu çalıştır
    asyncio.run(async_scan_manager(targets, ports_to_scan, timeout, args.delay, scan_mode, open_ports, thread_count))
    
    duration = time.time() - start_time
    
    print("-" * 60)
    print(f" Tarama {duration:.2f} saniyede tamamlandı.")
    print(f" Toplam {len(open_ports)} adet açık port bulundu.")
    print("-" * 60)

    if args.output:
        save_results(args.output, targets, open_ports, duration)

if __name__ == "__main__":
    main()
