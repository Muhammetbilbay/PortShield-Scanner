from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import scanner
import asyncio
import os
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(title="PortShield Scanner Web UI")
templates = Jinja2Templates(directory="templates")

# Tarama sonuçlarını geçici olarak hafızada saklayan değişken
last_scan_results = {
    "target": "",
    "ports": "",
    "scan_mode": "",
    "results": [],
    "subdomains": [],
    "directories": []
}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html", context={"results": None, "subdomains": None, "directories": None, "error": None})

@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request, 
    target: str = Form(...), 
    ports: str = Form(""), 
    top_ports: int = Form(0),
    delay: int = Form(0), 
    udp: bool = Form(False),
    subdomain_scan: bool = Form(False),
    dir_scan: bool = Form(False)
):
    open_ports = []
    scan_mode = "UDP" if udp else "TCP"
    error_msg = None
    
    # Hedefleri çözümle
    targets = scanner.parse_targets(target)
    if not targets:
        error_msg = "Geçersiz hedef adresi girdiniz!"
        return templates.TemplateResponse(request=request, name="index.html", context={"results": None, "subdomains": None, "directories": None, "error": error_msg})
    
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
        max_workers=100
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
                    
    # Sonuçları PDF indirme için sakla
    global last_scan_results
    last_scan_results = {
        "target": target,
        "ports": ports_str,
        "scan_mode": scan_mode,
        "results": results_list,
        "subdomains": subdomains_list,
        "directories": directories_list
    }
        
    return templates.TemplateResponse(request=request, name="index.html", context={
        "results": results_list,
        "subdomains": subdomains_list,
        "directories": directories_list,
        "target": target,
        "ports": ports_str,
        "scan_mode": scan_mode,
        "error": None
    })

@app.get("/download/pdf")
async def download_pdf():
    buffer = BytesIO()
    # Kenar boşlukları ayarlı döküman oluştur
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'TitleStyle',
        parent=styles['Heading1'],
        fontSize=24,
        textColor=colors.HexColor('#1A365D'),
        spaceAfter=15
    )
    h2_style = ParagraphStyle(
        'H2Style',
        parent=styles['Heading2'],
        fontSize=16,
        textColor=colors.HexColor('#2B6CB0'),
        spaceBefore=15,
        spaceAfter=10
    )
    normal_style = styles['Normal']
    
    # Rapor Başlığı
    story.append(Paragraph("PortShield Sızma Testi Raporu", title_style))
    story.append(Paragraph(f"Hedef: {last_scan_results['target']}", normal_style))
    story.append(Paragraph(f"Taranan Portlar: {last_scan_results['ports']}", normal_style))
    story.append(Paragraph(f"Tarama Modu: {last_scan_results['scan_mode']}", normal_style))
    story.append(Spacer(1, 15))
    
    # Bulgular Tablosu
    story.append(Paragraph("Açık Port Bulguları", h2_style))
    table_data = [["IP Adresi", "Port", "Servis", "Analiz / Uyarılar"]]
    for item in last_scan_results["results"]:
        warns = "\n".join(item["warnings"]) if item["warnings"] else "Temiz / Sorun yok"
        table_data.append([item["ip"], str(item["port"]), item["banner"], warns])
        
    t = Table(table_data, colWidths=[100, 50, 150, 240])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2B6CB0')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('BOTTOMPADDING', (0,0), (-1,0), 8),
        ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#F7FAFC')])
    ]))
    story.append(t)
    
    # Subdomain Bulguları
    if last_scan_results["subdomains"]:
        story.append(Spacer(1, 15))
        story.append(Paragraph("Keşfedilen Alt Alan Adları (Subdomains)", h2_style))
        sub_data = [["Subdomain", "IP Adresi"]]
        for sub, ip in last_scan_results["subdomains"]:
            sub_data.append([sub, ip])
        t_sub = Table(sub_data, colWidths=[270, 270])
        t_sub.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2D3748')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ]))
        story.append(t_sub)
        
    # Dizin Bulguları
    if last_scan_results["directories"]:
        story.append(Spacer(1, 15))
        story.append(Paragraph("Keşfedilen Gizli Web Dizinleri", h2_style))
        dir_data = [["URL", "Durum Kodu"]]
        for item in last_scan_results["directories"]:
            dir_data.append([f"{item['ip']}:{item['port']}{item['path']}", str(item['status'])])
        t_dir = Table(dir_data, colWidths=[400, 140])
        t_dir.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2D3748')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('GRID', (0,0), (-1,-1), 1, colors.grey),
        ]))
        story.append(t_dir)
        
    doc.build(story)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=portshield_rapor.pdf"})
