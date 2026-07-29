from fastapi import FastAPI, Request, Form, BackgroundTasks
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import scanner
import asyncio
import os
import json
import csv
from io import BytesIO, StringIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

app = FastAPI(title="PortShield Scanner Web UI")
templates = Jinja2Templates(directory="templates")

# Türkçe karakter desteği için Arial yazı tipini sisteme kaydet
pdf_font = 'Helvetica'
pdf_font_bold = 'Helvetica-Bold'
try:
    font_path = "C:\\Windows\\Fonts\\arial.ttf"
    font_bold_path = "C:\\Windows\\Fonts\\arialbd.ttf"
    if os.path.exists(font_path) and os.path.exists(font_bold_path):
        pdfmetrics.registerFont(TTFont('Arial', font_path))
        pdfmetrics.registerFont(TTFont('Arial-Bold', font_bold_path))
        pdf_font = 'Arial'
        pdf_font_bold = 'Arial-Bold'
except Exception:
    pass

# Tarama sonuçlarını geçici olarak hafızada saklayan değişken
last_scan_results = {
    "target": "",
    "ports": "",
    "scan_mode": "",
    "results": [],
    "subdomains": [],
    "directories": [],
    "apis": [],
    "geolocation": None
}

# Zamanlanmış görevler listesi
scheduled_scans = []

async def run_scheduled_scan(target: str, interval_seconds: int, email: str = None):
    """
    Arka planda belirli aralıklarla çalışacak zamanlanmış tarama görevi.
    """
    while True:
        await asyncio.sleep(interval_seconds)
        open_ports = []
        targets = scanner.parse_targets(target)
        if targets:
            await scanner.async_scan_manager(
                targets=targets,
                ports=scanner.TOP_PORTS[10],
                timeout=1.0,
                delay=0,
                scan_mode="TCP",
                open_ports=open_ports,
                max_workers=50
            )
            print(f"[ZAMANLAYICI] {target} adresi otomatik olarak tarandı. Açık port adeti: {len(open_ports)}")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"results": None, "subdomains": None, "directories": None, "apis": None, "geolocation": None, "error": None, "scheduled": scheduled_scans})

@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request, 
    target: str = Form(...), 
    ports: str = Form(""), 
    top_ports: int = Form(0),
    delay: int = Form(0), 
    udp: bool = Form(False),
    subdomain_scan: bool = Form(False),
    dir_scan: bool = Form(False),
    brute_force: bool = Form(False),
    waf_detect: bool = Form(False),
    api_scan: bool = Form(False)
):
    open_ports = []
    scan_mode = "UDP" if udp else "TCP"
    error_msg = None
    
    # Hedefleri çözümle
    targets = scanner.parse_targets(target)
    if not targets:
        error_msg = "Geçersiz hedef adresi girdiniz!"
        return templates.TemplateResponse(request=request, name="index.html", context={"results": None, "subdomains": None, "directories": None, "apis": None, "geolocation": None, "error": error_msg, "scheduled": scheduled_scans})
    
    # Portları belirle
    if top_ports > 0:
        ports_to_scan = scanner.TOP_PORTS.get(top_ports, scanner.TOP_PORTS[10])
        ports_str = f"Top {top_ports}"
    elif ports.strip():
        ports_to_scan = scanner.parse_ports(ports)
        ports_str = ports
    else:
        ports_to_scan = scanner.TOP_PORTS[10]
        ports_str = "Top 10 (Varsayılan)"
        
    # Asenkron port taramasını başlat
    await scanner.async_scan_manager(
        targets=targets, 
        ports=ports_to_scan, 
        timeout=1.0, 
        delay=delay, 
        scan_mode=scan_mode, 
        open_ports=open_ports, 
        max_workers=100,
        brute_force=brute_force,
        waf_detect=waf_detect
    )
    
    # Sonuçları formatla
    results_list = []
    for ip, port, banner, warnings in open_ports:
        results_list.append({
            "ip": ip,
            "port": port,
            "banner": banner,
            "warnings": warnings
        })
        
    # Opsiyonel: Subdomain Taraması
    subdomains_list = []
    if subdomain_scan and not target.replace('.', '').replace('-', '').isdigit():
        subdomains_list = await scanner.discover_subdomains(target)
        
    # Opsiyonel: Web Dizin Taraması
    directories_list = []
    if dir_scan:
        for ip, port, banner, warnings in open_ports:
            if port in [80, 8080, 443, 8443]:
                found_dirs = await scanner.brute_force_directories(ip, port)
                for path, status in found_dirs:
                    directories_list.append({
                        "ip": ip,
                        "port": port,
                        "path": path,
                        "status": status
                    })

    # Opsiyonel: API & Swagger Keşfi
    apis_list = []
    if api_scan:
        for ip, port, banner, warnings in open_ports:
            if port in [80, 8080, 443, 8443]:
                found_apis = await scanner.discover_api_endpoints(ip, port)
                for path, status in found_apis:
                    apis_list.append({
                        "ip": ip,
                        "port": port,
                        "path": path,
                        "status": status
                    })

    # Coğrafi Konum (IP Geolocation) Sorgula
    geo_data = None
    if targets:
        geo_data = await asyncio.to_thread(scanner.get_ip_geolocation, targets[0])
                    
    # Sonuçları PDF indirme için sakla
    global last_scan_results
    last_scan_results = {
        "target": target,
        "ports": ports_str,
        "scan_mode": scan_mode,
        "results": results_list,
        "subdomains": subdomains_list,
        "directories": directories_list,
        "apis": apis_list,
        "geolocation": geo_data
    }
        
    return templates.TemplateResponse(request=request, name="index.html", context={
        "results": results_list,
        "subdomains": subdomains_list,
        "directories": directories_list,
        "apis": apis_list,
        "geolocation": geo_data,
        "target": target,
        "ports": ports_str,
        "scan_mode": scan_mode,
        "error": None,
        "scheduled": scheduled_scans
    })

@app.post("/schedule")
async def schedule(
    background_tasks: BackgroundTasks,
    target: str = Form(...),
    interval: int = Form(...)
):
    """
    Belirtilen hedef için arka plan görevi olarak otomatik tarama kurar.
    """
    interval_seconds = interval * 60
    background_tasks.add_task(run_scheduled_scan, target, interval_seconds)
    scheduled_scans.append({
        "target": target,
        "interval": interval
    })
    return HTMLResponse("<script>alert('Zamanlanmış Tarama Arka Planda Başlatıldı!'); window.location.href='/';</script>")

@app.get("/download/pdf")
async def download_pdf():
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontName=pdf_font_bold,
        fontSize=24,
        textColor=colors.HexColor('#1A365D'),
        spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontName=pdf_font_bold,
        fontSize=16,
        textColor=colors.HexColor('#2B6CB0'),
        spaceBefore=15,
        spaceAfter=10
    )
    normal_style = ParagraphStyle(
        'NormalStyle',
        parent=styles['Normal'],
        fontName=pdf_font,
        fontSize=10,
        textColor=colors.HexColor('#2D3748'),
        spaceAfter=5
    )
    cell_style = ParagraphStyle(
        'CellStyle',
        parent=styles['Normal'],
        fontName=pdf_font,
        fontSize=9,
        leading=12
    )
    header_cell_style = ParagraphStyle(
        'HeaderCellStyle',
        parent=styles['Normal'],
        fontName=pdf_font_bold,
        fontSize=10,
        textColor=colors.white
    )
    
    # Rapor Başlığı
    story.append(Paragraph("PortShield Sızma Testi Raporu", title_style))
    story.append(Paragraph(f"<b>Hedef:</b> {last_scan_results['target']}", normal_style))
    story.append(Paragraph(f"<b>Taranan Portlar:</b> {last_scan_results['ports']}", normal_style))
    story.append(Paragraph(f"<b>Tarama Modu:</b> {last_scan_results['scan_mode']}", normal_style))
    
    # Konum bilgileri varsa ekle
    geo = last_scan_results.get("geolocation")
    if geo:
        story.append(Paragraph(f"<b>Coğrafi Konum:</b> {geo['city']}, {geo['country']} | <b>ISS (ISP):</b> {geo['isp']}", normal_style))
        
    story.append(Spacer(1, 15))
    
    # Bulgular Tablosu
    story.append(Paragraph("Açık Port Bulguları", h2_style))
    table_data = [[
        Paragraph("IP Adresi", header_cell_style), 
        Paragraph("Port", header_cell_style), 
        Paragraph("Servis", header_cell_style), 
        Paragraph("Analiz / Uyarılar", header_cell_style)
    ]]
    for item in last_scan_results["results"]:
        warns = "<br/>".join(item["warnings"]) if item["warnings"] else "Temiz / Sorun yok"
        table_data.append([
            Paragraph(item["ip"], cell_style),
            Paragraph(str(item["port"]), cell_style),
            Paragraph(item["banner"], cell_style),
            Paragraph(warns, cell_style)
        ])
        
    t = Table(table_data, colWidths=[100, 50, 150, 240])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2B6CB0')),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F7FAFC')])
    ]))
    story.append(t)
    
    # Subdomain Bulguları
    if last_scan_results["subdomains"]:
        story.append(Spacer(1, 15))
        story.append(Paragraph("Keşfedilen Alt Alan Adları (Subdomains)", h2_style))
        sub_data = [[
            Paragraph("Subdomain", header_cell_style), 
            Paragraph("IP Adresi", header_cell_style)
        ]]
        for sub, ip in last_scan_results["subdomains"]:
            sub_data.append([
                Paragraph(sub, cell_style), 
                Paragraph(ip, cell_style)
            ])
        t_sub = Table(sub_data, colWidths=[270, 270])
        t_sub.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2D3748')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F7FAFC')])
        ]))
        story.append(t_sub)
        
    # Dizin Bulguları
    if last_scan_results["directories"]:
        story.append(Spacer(1, 15))
        story.append(Paragraph("Keşfedilen Gizli Web Dizinleri", h2_style))
        dir_data = [[
            Paragraph("URL", header_cell_style), 
            Paragraph("Durum Kodu", header_cell_style)
        ]]
        for item in last_scan_results["directories"]:
            dir_data.append([
                Paragraph(f"{item['ip']}:{item['port']}{item['path']}", cell_style), 
                Paragraph(str(item['status']), cell_style)
            ])
        t_dir = Table(dir_data, colWidths=[400, 140])
        t_dir.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2D3748')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F7FAFC')])
        ]))
        story.append(t_dir)

    # API Dokümantasyon Bulguları
    if last_scan_results.get("apis"):
        story.append(Spacer(1, 15))
        story.append(Paragraph("Keşfedilen API ve Swagger Dokümantasyonları", h2_style))
        api_data = [[
            Paragraph("API Adresi (URL)", header_cell_style), 
            Paragraph("Durum Kodu", header_cell_style)
        ]]
        for item in last_scan_results["apis"]:
            api_data.append([
                Paragraph(f"{item['ip']}:{item['port']}{item['path']}", cell_style), 
                Paragraph(str(item['status']), cell_style)
            ])
        t_api = Table(api_data, colWidths=[400, 140])
        t_api.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1A365D')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('VALIGN', (0,0), (-1,-1), 'TOP'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('TOPPADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F7FAFC')])
        ]))
        story.append(t_api)
        
    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=portshield_rapor.pdf"})

@app.get("/download/json")
async def download_json():
    """
    Tarama verilerini ham JSON formatında indirmeyi sağlar.
    """
    json_bytes = json.dumps(last_scan_results, indent=4, ensure_ascii=False).encode('utf-8')
    return StreamingResponse(BytesIO(json_bytes), media_type="application/json", headers={"Content-Disposition": "attachment; filename=portshield_rapor.json"})

@app.get("/download/csv")
async def download_csv():
    """
    Tarama verilerini Excel uyumlu Türkçe CSV formatında indirmeyi sağlar.
    """
    csv_buffer = StringIO()
    writer = csv.writer(csv_buffer, delimiter=';')
    writer.writerow(["IP Adresi", "Port", "Servis / Banner", "Zafiyetler ve Bulgular"])
    
    for item in last_scan_results["results"]:
        warns = " | ".join(item["warnings"]) if item["warnings"] else "Sorun Yok"
        writer.writerow([item["ip"], item["port"], item["banner"], warns])
        
    csv_bytes = csv_buffer.getvalue().encode('utf-8-sig') # BOM ekle
    return StreamingResponse(BytesIO(csv_bytes), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=portshield_rapor.csv"})
