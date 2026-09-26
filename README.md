
<div align="center">


# 🔮 OLHO MALIGNO™

### *~ scanner.exe has entered the chat ~*

**v7.0.0-UNIFIED // 100% freeware // no spyware (we promise)**

<img src="https://media.giphy.com/media/3o72F8t9TDi2xVnxOE/giphy.gif" width="150"/>

`[||||||||||||||||||||] 100% loaded`

</div>

---

+---------------------------------------------------------------+
|  olho_maligno.py - Executando...                              |
|  ___________________________________________________________  |
|  Alvo: https://alvo-autorizado.com                            |
|  Status: SCANNING ████████████████░░ 87%                      |
|                                                               |
|              [ CANCELAR ]   [  OK  ]                          |
+---------------------------------------------------------------+
plain


> 🖥️ **best viewed in Internet Explorer 6.0 @ 800x600, millions of colors**
> 💾 don't forget to sign the guestbook before you leave!!

---

## ☆ Sobre este programa ☆

**OLHO MALIGNO** é um scanner de vulnerabilidades web **single-file** feito em Python, pra pentesters, bug bounty hunters e analistas de segurança que operam **EXCLUSIVAMENTE** em ambientes autorizados.

zero bloat. zero build. um arquivo `.py` e vai. old school assim 🤙

<div align="center">

![under construction](https://media.giphy.com/media/WFZvB7VIXBgiz3oDXE/giphy.gif)
*always under construction since 2003*

</div>

---

## ⚠️ AVISO LEGAL (leia ou o Clippy fica triste)

┌──────────────────────────────────────────────┐
│ 🚨 ESTE SOFTWARE É PARA USO AUTORIZADO SÓ    │
│                                                │
│  ✅ Programas de Bug Bounty                   │
│  ✅ Pentest com contrato assinado             │
│  ✅ Labs / CTF / localhost                    │
│                                                │
│  ❌ Scanear terceiros sem permissão = CRIME   │
│     (Lei 12.737/2012 - Carolina Dieckmann)    │
└──────────────────────────────────────────────┘
plain


**não somos responsáveis pelo que você faz às 3 da manhã. scan responsável. ☮️**

---

## 🚀 Features (aka "o que o bichinho faz")

| módulo | descrição | status |
|--------|-----------|--------|
| 🔍 **Recon** | enumeração de endpoints comuns (`/admin`, `/.env`, `/graphql`...) | ✅ rodando |
| 💉 **SQLi** | time-based, error-based + payloads union | ✅ rodando |
| 🎯 **XSS** | refletido via marker injection | ✅ rodando |
| 📁 **LFI** | path traversal + `/etc/passwd` detection | ✅ rodando |
| 🚪 **IDOR** | enumeração de IDs + diff de respostas | ✅ rodando |
| ☁️ **SSRF** | cloud metadata + portas internas | ✅ rodando |
| 💣 **RCE** | command injection (`id`) | ✅ rodando |
| 🔑 **Sensitive Files** | `.env`, `.git/config`, `.aws/credentials`... | ✅ rodando |
| 🌐 **IP Lookup** | geolocalização via `ipinfo.io` | ✅ rodando |
| 📊 **Reports** | JSON / Markdown / HTML com CSS inline | ✅ rodando |
| 🕷️ **Web Crawler** | spider automático | 🚧 roadmap |
| 🌍 **Subdomain Enum** | brute de subdomínios | 🚧 roadmap |
| 📁 **RFI** | remote file inclusion | 🚧 roadmap |

> ps: o README antigo prometia crawler/subdomínio/RFI como prontos — mentira. agora tá certo. 🤥➡️😇

---

## 📥 Download & Instalação

# 1. baixa o arquivo (sim, é só UM arquivo)
wget https://raw.githubusercontent.com/seu-user/olho-maligno/main/olho_maligno.py

# 2. instala as 2 dependências (requests + colorama)
pip install requests colorama

# 3. corre
python olho_maligno.py scan https://seu-lab-local.com

requirements: Python 3.9+ / funciona no Windows XP* / Linux / macOS
<small>
🎮 Como usar
plain

$ python olho_maligno.py scan https://alvo.com

Table
flag	o que faz
--proxy http://127.0.0.1:8080	joga tudo pro Burp pra inspeção manual
--delay 2	modo safe: 2s entre requests (default 0.5)
--format json|md|html	formato do relatório
--output relatorio	nome base do arquivo
bash

# exemplos práticos
python olho_maligno.py scan https://testphp.vulnweb.com --delay 1
python olho_maligno.py scan https://alvo.com --proxy http://127.0.0.1:8080 --format html
python olho_maligno.py lookup 8.8.8.8

    💡 dica de profissional: use --delay 1 ou maior em alvos reais. WAF gosta de scanner rápido assim como sua mãe gosta de pop-up: não gosta.

📸 Screenshot
plain

╔══════════════════════════════════════════╗
║ 🔮 OLHO MALIGNO v7.0.0-UNIFIED           ║
║ Alvo: http://testphp.vulnweb.com         ║
╚══════════════════════════════════════════╝
[*] Scanning: SQL Injection
  -> 1 findings
[CRÍTICA] 1 vulnerabilidade(s)

  1. SQL Injection (Time-Based Blind)
     URL: http://testphp.vulnweb.com/listproducts.php?cat=
     CVSS: 9.8 | Bounty: $3000+

<div align="center">
https://media.giphy.com/media/AOSwwqVjNZlDO/giphy.gif
</div>
🗺️ Roadmap (aka "wishlist")

    [ ] web crawler real (BeautifulSoup spider)
    [ ] subdomain enumeration (wordlist-based)
    [ ] RFI detection
    [ ] CORS misconfig detector
    [ ] open redirect fuzzing
    [ ] modo "stealth" (user-agent rotation)
    [ ] integração Burp Suite (export)

🤝 Contribua
PRs são bem-vindos!!1 abre uma issue, manda o patch, whatever. código single-file de propósito — menos é mais. se sua contribuição adicionar dependência, ela precisa se justificar MUITO.
📜 Licença
MIT — faz o que quiser, mas scan não autorizado é crime e essa licença não te protege de nada disso. 👮
<div align="center">
<img src="https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif" width="300"/>
obrigado por visitar!!! volte sempre!!
https://img.shields.io/badge/visitors-13337-blue?style=plastic
https://img.shields.io/badge/hits-because%20it's%20the%20vibe-ff69b4?style=plastic
https://img.shields.io/badge/made%20with-python%20%26%20nostalgia-yellowgreen?style=plastic
last updated: 09/26/2026 @ 13:40 — [meu diário secreto] [fotos] [links] [guestbook]
</div>
```
