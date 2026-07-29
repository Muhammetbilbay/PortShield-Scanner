from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import scanner
import asyncio
import os

app = FastAPI(title="PortShield Scanner Web UI")

# HTML şablonları için templates klasörünü tanımla
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "results": None, "error": None})

@app.post("/scan", response_class=HTMLResponse)
async def scan(
    request: Request, 
    target: str = Form(...), 
    ports: str = Form(""), 
    top_ports: int = Form(0),
    delay: int = Form(0), 
    udp: bool = Form(False)
):
    open_ports = []
    scan_mode = "UDP" if udp else "TCP"
    error_msg = None
    
    # Hedefleri çözümle
    targets = scanner.parse_targets(target)
    if not targets:
        error_msg = "Geçersiz hedef adresi girdiniz!"
        return templates.TemplateResponse("index.html", {"request": request, "results": None, "error": error_msg})
    
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
        
    # Asenkron taramayı başlat
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
        
    return templates.TemplateResponse("index.html", {
        "request": request,
        "results": results_list,
        "target": target,
        "ports": ports_str,
        "scan_mode": scan_mode,
        "error": None
    })
