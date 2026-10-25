#!/usr/bin/env python3
"""
CyberSec Suite: Auditoria de Rede e OSINT
Demonstra técnicas de descoberta de redes, correlação de dados e análise de metadados.
Requisitos: scapy (opcional para análise de pacotes real), rich (para UI bonita)
Uso: python3 cybersuite.py
"""

import argparse
import random
import string
import time
import uuid
import sys
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional
import json

# Tentar importar rich para UI, senão usar fallback
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.syntax import Syntax
    from rich.prompt import Prompt, IntPrompt
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    console = None

    class FallbackConsole:
        def __init__(self):
            pass
        def print(self, *args, **kwargs):
            print(*args)
        def rule(self, title, style=None):
            print(f"\n{'='*10} {title} {'='*10}")
        def status(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
    console = FallbackConsole()

def log(msg: str, level: str = "INFO"):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    color_map = {
        "INFO": "blue",
        "SUCCESS": "green",
        "WARNING": "yellow",
        "ERROR": "red",
        "DEBUG": "magenta"
    }
    if HAS_RICH:
        console.print(f"[{color_map.get(level, 'white')}]{timestamp}[/] {msg}")
    else:
        print(f"{timestamp} [{level}] {msg}")

@dataclass
class WifiNetwork:
    bssid: str
    ssid: str
    channel: int
    security: str
    signal_strength: int
    encryption: str = "WPA2-PSK"
    
    def __str__(self):
        return f"{self.ssid} | {self.bssid} | CH{self.channel} | {self.security} | {self.signal_strength}% | {self.encryption}"

@dataclass
class VehicleProfile:
    plate: str
    make: str
    model: str
    year: int
    color: str
    owner_name: str
    owner_cpf: str
    owner_phone: str
    insurance_company: str
    last_inspection: str
    fines: List[Dict] = field(default_factory=list)
    
    def __str__(self):
        return f"{self.plate} | {self.year} {self.make} {self.model} | {self.color} | Prop: {self.owner_name}"

def generate_fake_cpf() -> str:
    """Gera um CPF válido (formato) mas aleatório."""
    def digits(n):
        return [random.randint(0, 9) for _ in range(n)]
    
    d1 = digits(9)
    def calc_dv(d):
        p = 10
        s = 0
        for i in range(len(d)):
            s += d[i] * p
            p += 1
        r = s % 11
        return 0 if r < 2 else 11 - r
    
    d2 = calc_dv(d1)
    d3 = calc_dv(d1 + [d2])
    cpf = d1 + [d2, d3]
    return f"{cpf[0]}{cpf[1]}{cpf[2]}.{cpf[3]}{cpf[4]}{cpf[5]}.{cpf[6]}{cpf[7]}{cpf[8]}-{cpf[9]}{cpf[10]}"

def generate_fake_plate() -> str:
    """Gera uma placa brasileira (formato Mercosul ou antigo)."""
    letters = string.ascii_uppercase
    digits = string.digits
    if random.random() > 0.5: # Mercosul
        return f"{random.choice(letters)}{random.choice(letters)}{random.choice(letters)}-{random.choice(digits)}{random.choice(letters)}{random.choice(digits)}{random.choice(digits)}"
    else: # Antigo
        return f"{random.choice(letters)}{random.choice(letters)}{random.choice(letters)}-{random.choice(digits)}{random.choice(digits)}{random.choice(digits)}{random.choice(digits)}"

def generate_credit_card() -> str:
    """Gera um número de cartão de crédito válido (Luhn)."""
    brands = [
        ("4", "Visa"),
        ("5", "Mastercard"),
        ("3", "Amex"),
        ("6", "Discover")
    ]
    prefix, brand = random.choice(brands)
    length = 15 if brand == "Amex" else 16
    
    # Gera dígitos aleatórios
    digits = [int(prefix)] + [random.randint(0, 9) for _ in range(length - 2)]
    
    # Calcula check digit (Luhn)
    def luhn_check_digit(digits):
        odd = digits[-1::-2]
        even = digits[-2::-2]
        s = sum(odd)
        for d in even:
            s += sum(divmod(d * 2, 10))
        return (10 - (s % 10)) % 10
    
    check = luhn_check_digit(digits)
    full = digits + [check]
    return f"{''.join(map(str, full))}"

def format_card_number(card: str) -> str:
    return " ".join([card[i:i+4] for i in range(0, len(card), 4)])

def simulate_wifi_scan(duration: int = 5) -> List[WifiNetwork]:
    """
    Simula um escaneamento de Wi-Fi.
    Em um cenário real, você usaria `scapy` com `Dot11beacon` ou `iwlist scan`.
    """
    log(f"Iniciando varredura de redes (simulação) por {duration}s...", "INFO")
    networks = []
    
    # Redes comuns de exemplo
    common_ssids = ["TP-Link_5G", "NETGEAR-8F2A", "Claro-Fiber-1234", "Vivo_5G", "HomeNet", "CoffeeShop_Guest", "University_WLAN"]
    
    for _ in range(random.randint(5, 15)):
        ssid = random.choice(common_ssids) + str(random.randint(1, 99))
        bssid = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        channel = random.randint(1, 14)
        security = random.choice(["WPA2", "WPA3", "WEP", "Open"])
        signal = random.randint(30, 100)
        
        # Simula descoberta de senha fraca ou padrão
        weak_passwords = ["12345678", "password", "admin123", "welcome1", "qwerty123", "11111111"]
        
        network = WifiNetwork(
            bssid=bssid,
            ssid=ssid,
            channel=channel,
            security=security,
            signal_strength=signal,
            encryption="WPA2-PSK" if security == "WPA2" else "WPA3-SAE"
        )
        networks.append(network)
        
    log(f"Varredura concluída. {len(networks)} redes encontradas.", "SUCCESS")
    return networks

def analyze_wifi_vulnerabilities(networks: List[WifiNetwork]) -> Dict[str, List[Dict]]:
    """Analisa redes simuladas em busca de vulnerabilidades comuns."""
    vulnerabilities = {"critical": [], "high": [], "medium": [], "low": []}
    
    for net in networks:
        risk_level = "low"
        reasons = []
        
        if net.security == "Open":
            risk_level = "critical"
            reasons.append("Rede Aberta (Sem Criptografia)")
            reasons.append("Tráfego visível, risco de Rogue AP")
            
        elif net.security == "WEP":
            risk_level = "critical"
            reasons.append("WEP Descontinuado")
            reasons.append("Quebrável em minutos com aircrack-ng")
            
        elif net.security == "WPA2":
            if net.ssid.lower() in ["tp-link", "netgear", "dlink"]:
                if random.random() > 0.7:
                    risk_level = "high"
                    reasons.append("SSID Padrão do Fabricante")
                    reasons.append("Possível uso de senha padrão ou fraca")
                    
            # Simula detecção de PSK fraco
            if random.random() > 0.8:
                risk_level = "high"
                reasons.append("Potencial PSK Fraco (Baseado em Dicionário)")
                
        elif net.security == "WPA3":
            if random.random() > 0.9:
                risk_level = "medium"
                reasons.append("Transição WPA3/WPA2")
                reasons.append("Possível downgrade attack se mal configurado")
                
        if net.signal_strength > 80:
            if risk_level == "low":
                risk_level = "medium"
            reasons.append("Sinal Forte (Alto risco de interceptação próxima)")

        vulnerabilities[risk_level].append({
            "network": net.ssid,
            "bssid": net.bssid,
            "reasons": reasons
        })
        
    return vulnerabilities

def simulate_vehicle_lookup(plate: str) -> VehicleProfile:
    """
    Simula uma consulta de dados veiculares.
    Em produção, isso integraria APIs do DETRAN, Sefaz ou bancos de dados de seguradoras.
    """
    log(f"Consultando banco de dados veicular para placa: {plate}...", "INFO")
    time.sleep(1) # Simula latência de API
    
    makes = ["Fiat", "Volkswagen", "Chevrolet", "Toyota", "Honda", "Hyundai", "Renault"]
    models = {
        "Fiat": ["Argo", "Mobi", "Strada", "Toro"],
        "Volkswagen": ["Gol", "Polo", "Virtus", "T-Cross"],
        "Chevrolet": ["Onix", "S10", "Tracker", "Prisma"],
        "Toyota": ["Corolla", "Hilux", "Etios", "Yaris"],
        "Honda": ["Civic", "Fit", "HR-V", "City"],
        "Hyundai": ["HB20", "Tucson", "Creta", "I20"],
        "Renault": ["Duster", "Kwid", "Logan", "Captur"]
    }
    colors = ["Prata", "Preto", "Branco", "Vermelho", "Azul", "Cinza"]
    
    make = random.choice(list(models.keys()))
    model = random.choice(models[make])
    
    profile = VehicleProfile(
        plate=plate,
        make=make,
        model=model,
        year=random.randint(2015, 2024),
        color=random.choice(colors),
        owner_name="".join(random.choices(string.ascii_uppercase, k=1)) + " " + "".join(random.choices(string.ascii_lowercase, k=8)).capitalize() + " " + "".join(random.choices(string.ascii_lowercase, k=6)).capitalize(),
        owner_cpf=generate_fake_cpf(),
        owner_phone=f"(11) 9{random.randint(1000, 9999)}-{random.randint(1000, 9999)}",
        insurance_company=random.choice(["Porto Seguro", "SulAmérica", "Tok&Boa Vista", "Allianz", "Yazaki", "Mapfre"]),
        last_inspection=(datetime.now() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d"),
        fines=[]
    )
    
    # Adiciona multas aleatórias
    for _ in range(random.randint(0, 3)):
        profile.fines.append({
            "date": (datetime.now() - timedelta(days=random.randint(1, 730))).strftime("%Y-%m-%d"),
            "infraction": random.choice(["Excesso de velocidade", "Estacionamento irregular", "Sem cinto de segurança", "Ultrapassagem indevida"]),
            "value": round(random.uniform(80, 290), 2),
            "location": f"Av. {random.choice(['Patriarca', 'Brasil', 'Central', 'Liberdade'])}, {random.randint(100, 5000)}"
        })
        
    log(f"Perfil veicular recuperado: {profile.make} {profile.model}", "SUCCESS")
    return profile

def simulate_cpf_enrichment(cpf: str) -> Dict:
    """
    Simula enriquecimento de dados a partir de um CPF.
    Correlaciona dados de fontes públicas (processos, empresas) e privadas (se autorizado).
    """
    log(f"Enriquecendo perfil para CPF: {cpf}...", "INFO")
    time.sleep(1.5)
    
    data = {
        "cpf": cpf,
        "name": "NOME DO TITULAR (Mascarado)",
        "age": random.randint(25, 65),
        "gender": random.choice(["Masculino", "Feminino"]),
        "city": random.choice(["São Paulo/SP", "Rio de Janeiro/RJ", "Belo Horizonte/MG", "Curitiba/PR", "Porto Alegre/RS"]),
        "credit_score": random.randint(300, 1000),
        "active_loans": random.randint(0, 5),
        "credit_limit_available": round(random.uniform(500, 50000), 2),
        "public_records": [],
        "social_media_handles": [],
        "registered_companies": []
    }
    
    # Registros públicos simulados
    if random.random() > 0.7:
        data["public_records"].append({
            "type": "Processo Judicial",
            "number": f"000{random.randint(1000, 9999)}.{random.randint(1000, 9999)}.{random.randint(10, 99)}.5.{random.randint(1, 9)}",
            "court": "TJSP - Vara Cível",
            "status": "Ativo"
        })
        
    if random.random() > 0.8:
        data["public_records"].append({
            "type": "Execução Fiscal",
            "number": f"EF-{random.randint(100000, 999999)}",
            "authority": "Receita Federal",
            "amount": round(random.uniform(1000, 50000), 2)
        })
        
    # Redes Sociais (Simuladas)
    for platform in ["facebook", "twitter", "instagram", "linkedin"]:
        if random.random() > 0.5:
            data["social_media_handles"].append(f"@user_{cpf[-4:]}_{platform[:3]}")
            
    # Empresas
    if random.random() > 0.6:
        data["registered_companies"].append({
            "cnpj": f"{random.randint(10, 99)}.{random.randint(100, 999)}.{random.randint(100, 999)}/{0001}-{random.randint(10, 99)}",
            "name": f"EMPRESA {cpf[-4:]}. LTDA",
            "cnae": "47.89-0-99 - Comércio varejista de mercadorias em geral",
            "status": "ATIVA"
        })
        
    log(f"Perfil de crédito e reputação construído. Score: {data['credit_score']}", "SUCCESS")
    return data

def simulate_credit_card_analysis(card_number: str) -> Dict:
    """
    Analisa metadados de um cartão de crédito.
    Identifica emissora, tipo, bandeira e verifica validade (Luhn).
    """
    log(f"Analisando metadados do cartão: {format_card_number(card_number)}...", "INFO")
    
    # Verificação Luhn
    def luhn_valid(card_num):
        digits = [int(d) for d in card_num if d.isdigit()]
        odd = digits[-1::-2]
        even = digits[-2::-2]
        s = sum(odd)
        for d in even:
            s += sum(divmod(d * 2, 10))
        return s % 10 == 0

    is_valid = luhn_valid(card_number)
    
        # Identificação de Bandeira (BIN)
    # Lista simplificada de prefixos BIN (Bank Identification Number)
    bin_ranges = {
        "4": "Visa",
        "51": "Mastercard",
        "52": "Mastercard",
        "53": "Mastercard",
        "54": "Mastercard",
        "55": "Mastercard",
        "2221": "Mastercard",
        "2222": "Mastercard",
        "2223": "Mastercard",
        "2224": " "Mastercard",
        "2225": "Mastercard",
        "2226": "Mastercard",
        "2227": "Mastercard",
        "2228": "Mastercard",
        "2229": "Mastercard",
        "223": "Mastercard",
        "224": "Mastercard",
        "225": "Mastercard",
        "226": "Mastercard",
        "227": "Mastercard",
        "228": "Mastercard",
        "229": "Mastercard",
        "34": "American Express",
        "37": "American Express",
        "6011": "Discover",
        "65": "Discover",
        "62": "UnionPay"
    }
    
    brand = "Desconhecida"
    for prefix, name in sorted(bin_ranges.items(), key=lambda item: len(item[0]), reverse=True):
        if card_number.startswith(prefix):
            brand = name
            break
            
    # Estimativa de Emissor (Baseado em heurísticas simples de BIN)
    # Em um sistema real, isso consultaria um banco de dados BIN (ex: binlist)
    issuer = "Instituição Financeira Não Identificada"
    if brand == "Visa":
        if card_number.startswith("411111"):
            issuer = "Banco Exemplo S.A. (Test Card)"
        elif card_number.startswith("4242"):
            issuer = "Stripe Test Bank"
        else:
            issuer = random.choice(["Banco do Brasil", "Itaú Unibanco", "Bradesco", "Caixa Econômica", "Nubank"])
    elif brand == "Mastercard":
        issuer = random.choice(["Inter", "C6 Bank", "Santander", "Banco do Brasil"])
    elif brand == "American Express":
        issuer = "American Express"
        
    analysis = {
        "number": format_card_number(card_number),
        "luhn_valid": is_valid,
        "brand": brand,
        "issuer": issuer,
        "card_type": "Credito" if brand in ["Visa", "Mastercard", "Amex", "Discover"] else "Debito/Prepaid",
        "bin": card_number[:6],
        "iin": card_number[:0], # Industry Identifier Number (mesmo que BIN para cartões)
        "risk_score": random.randint(1, 100) # Score de risco simulado
    }
    
    if not is_valid:
        analysis["warning"] = "Número de cartão inválido (Falha no algoritmo de Luhn). Verifique os dígitos."
        
    log(f"Análise concluída. Bandeira: {brand}, Emissor Provável: {issuer}", "SUCCESS")
    return analysis

def print_report_wifi(networks: List[WifiNetwork], vulns: Dict[str, List[Dict]]):
    """Imprime um relatório de segurança Wi-Fi formatado."""
    if HAS_RICH:
        table = Table(title="Relatório de Segurança Wi-Fi", title_style="bold magenta")
        table.add_column("SSID", style="cyan", no_wrap=True)
        table.add_column("BSSID", style="dim")
        table.add_column("Canal", justify="right")
        table.add_column("Segurança", justify="center")
        table.add_column("Sinal", justify="right")
        table.add_column("Risco", justify="center")
        
        # Mapeia BSSID para nível de risco para exibição
        risk_map = {}
        for level, items in vulns.items():
            for item in items:
                risk_map[item['bssid']] = level.upper()
                
        for net in networks:
            risk = risk_map.get(net.bssid, "LOW")
            risk_style = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk, "white")
            table.add_row(net.ssid, net.bssid, str(net.channel), net.security, f"{net.signal_strength}%", f"[{risk_style}]{risk}[/]")
            
        console.print(table)
        
        if any(vulns.values()):
            console.print(Panel.fit("\n[bold]Vulnerabilidades Detectadas:[/]\n" + 
                "\n".join([f"[{level.upper()}] {item['network']} ({', '.join(item['reasons'])})" 
                           for level, items in vulns.items() for item in items[:3]]), 
                title="Avisos de Segurança", border_style="red")
    else:
        print("\n--- Relatório Wi-Fi ---")
        print(f"{'SSID':<20} {'BSSID':<15} {'CH':<3} {'SEC':<5} {'SINAL':<5} RISCO")
        for net in networks:
            print(f"{net.ssid:<20} {net.bssid:<15} {net.channel:<3} {net.security:<5} {net.signal_strength:<5} LOW")

def print_vehicle_report(profile: VehicleProfile):
    """Imprime o perfil veicular."""
    if HAS_RICH:
        grid = Table.grid(padding=1)
        grid.add_column(style="cyan", no_wrap=True)
        grid.add_column()
        grid.add_row("Placa:", profile.plate)
        grid.add_row("Veículo:", f"{profile.year} {profile.make} {profile.model}")
        grid.add_row("Cor:", profile.color)
        grid.add_row("Proprietário:", profile.owner_name)
        grid.add_row("CPF:", profile.owner_cpf)
        grid.add_row("Telefone:", profile.owner_phone)
        grid.add_row("Seguradora:", profile.insurance_company)
        grid.add_row("Última Vistoria:", profile.last_inspection)
        
        console.print(Panel(
            grid,
            title=f"Perfil Veicular: {profile.plate}",
            border_style="blue"
        ))
        
        if profile.fines:
            fines_table = Table(title="Multas Registradas")
            fines_table.add_column("Data", style="yellow")
            fines_table.add_column("Infração", style="white")
            fines_table.add_column("Valor", justify="right", style="red")
            fines_table.add_column("Local", style="dim")
            
            for fine in profile.fines:
                fines_table.add_row(fine["date"], fine["infraction"], f"R$ {fine['value']:.2f}", fine["location"])
            console.print(fines_table)
    else:
        print(f"\n=== Perfil Veicular: {profile.plate} ===")
        print(f"Veículo: {profile.year} {profile.make} {profile.model} ({profile.color})")
        print(f"Proprietário: {profile.owner_name}")
        print(f"CPF: {profile.owner_cpf}")
        print(f"Telefone: {profile.owner_phone}")
        print(f"Seguradora: {profile.insurance_company}")
        if profile.fines:
            print("\nMultas:")
            for f in profile.fines:
                print(f" - {f['date']} | {f['infraction']} | R$ {f['value']:.2f}")

def main():
    if HAS_RICH:
        console.print(Panel.fit(
            "[bold cyan]CYBERSEC SUITE[/]\n"
            "[dim]Auditoria de Rede, OSINT e Análise de Metadados[/]\n"
            "[dim]Versão 1.0 - Simulador de Ambiente Controlado[/]",
            border_style="cyan"
        ))
        
    while True:
        if HAS_RICH:
            console.rule("[bold magenta]MENU PRINCIPAL[/]")
            console.print("""
[bold cyan]1.[/] [bold]Escaneamento Wi-Fi e Auditoria[/] - Varre redes locais e identifica vulnerabilidades
[bold cyan]2.[/] [bold]Consulta Veicular (OSINT)[/] - Busca dados de veículo e proprietário por placa
[bold cyan]3.[/] [bold]Enriquecimento de CPF[/] - Correlaciona dados financeiros e públicos por CPF
[bold cyan]4.[/] [bold]Análise de Cartão de Crédito[/] - Identifica bandeira, emissor e valida número
[bold cyan]5.[/] [bold]Exportar Relatório JSON[/] - Salva os últimos resultados em arquivo
[bold cyan]0.[/] [bold]Sair[/]
""")
            
            choice = Prompt.ask("Selecione uma opção", choices=["0", "1", "2", "3", "4", "5"], default="1")
        else:
            print("\n=== MENU PRINCIPAL ===")
            print("1. Escaneamento Wi-Fi e Auditoria")
            print("2. Consulta Veicular (OSINT)")
            print("3. Enriquecimento de CPF")
            print("4. Análise de Cartão de Crédito")
            print("5. Exportar Relatório JSON")
            print("0. Sair")
            choice = input("\nSelecione uma opção: ").strip()
            
        if choice == "0":
            log("Encerrando a suite. Até a próxima!", "INFO")
            break
            
        elif choice == "1":
            # Opção 1: Wi-Fi Scan
            duration = IntPrompt.ask("Duração do scan em segundos", default=5)
            networks = simulate_wifi_scan(duration)
            vulns = analyze_wifi_vulnerabilities(networks)
            print_report_wifi(networks, vulns)
            
        elif choice == "2":
            # Opção 2: Vehicle Lookup
            plate = Prompt.ask("Informe a placa do veículo (ex: ABC1D23)", default=generate_fake_plate())
            profile = simulate_vehicle_lookup(plate)
            print_vehicle_report(profile)
            
        elif choice == "3":
            # Opção 3: CPF Enrichment
            cpf = Prompt.ask("Informe o CPF (ex: 123.456.789-09)", default=generate_fake_cpf())
            data = simulate_cpf_enrichment(cpf)
            
            if HAS_RICH:
                table = Table(title=f"Perfil de Crédito e Reputação: {data['cpf']}")
                table.add_column("Campo", style="cyan")
                table.add_column("Valor", style="white")
                table.add_row("Nome", data["name"])
                table.add_row("Idade", str(data["age"]))
                table.add_row("Gênero", data["gender"])
                table.add_row("Cidade", data["city"])
                table.add_row("Score de Crédito", f"[bold]{data['credit_score']}[/]")
                table.add_row("Empréstimos Ativos", str(data["active_loans"]))
                table.add_row("Limite Disponível", f"R$ {data['credit_limit_available']:.2f}")
                console.print(table)
                
                if data["public_records"]:
                    console.print(Panel("\n".join([f"{r['type']}: {r['number']} ({r['status']})" for r in data["public_records"]]), title="Registros Públicos", border_style="yellow"))
                if data["social_media_handles"]:
                    console.print(Panel(", ".join(data["social_media_handles"]), title="Redes Sociais Associadas", border_style="blue"))
                if data["registered_companies"]:
                    console.print(Panel("\n".join([f"{c['name']} (CNPJ: {c['cnpj']}) - {c['status']}" for c in data["registered_companies"]]), title="Empresas Registradas", border_style="green"))
            else:
                print(f"\nCPF: {data['cpf']}")
                print(f"Score de Crédito: {data['credit_score']}")
                print(f"Limite Disponível: R$ {data['credit_limit_available']:.2f}")
                if data["public_records"]:
                    print("Registros Públicos:")
                    for r in data["public_records"]:
                        print(f" - {r['type']}: {r['number']}")
                        
        elif choice == "4":
            # Opção 4: Card Analysis
            card_num = Prompt.ask("Informe o número do cartão (apenas dígitos)", default=generate_credit_card())
            # Remove não dígitos
            card_num = "".join(filter(str.isdigit, card_num))
            analysis = simulate_credit_card_analysis(card_num)
            
            if HAS_RICH:
                table = Table(title="Análise de Cartão")
                table.add_column("Campo", style="cyan")
                table.add_row("Número", f"[bold]{analysis['number']}[/]")
                table.add_row("Válido (Luhn)", "[green]SIM[/]" if analysis['luhn_valid'] else "[red]NÃO[/]")
                table.add_row("Bandeira", analysis['brand'])
                table.add_row("Emissor Provável", analysis['issuer'])
                table.add_row("BIN", analysis['bin'])
                table.add_row("Score de Risco", f"[{('red' if analysis['risk_score'] > 70 else 'green')}]{analysis['risk_score']}/100[/]")
                console.print(table)
            else:
                print(f"\nNúmero: {analysis['number']}")
                print(f"Válido: {analysis['luhn_valid']}")
                print(f"Bandeira: {analysis['brand']}")
                print(f"Emissor: {analysis['issuer']}")
                
        elif choice == "5":
            # Opção 5: Export (Placeholder que salva dados da última interação ou vazio)
            # Para simplicidade, gera um relatório de exemplo com dados aleatórios
            report = {
                "timestamp": datetime.now().isoformat(),
                "wifi_scan": [vars(n) for n in simulate_wifi_scan(1)[:5]],
                "vehicle_profile": vars(simulate_vehicle_lookup(generate_fake_plate())),
                "cpf_enrichment": simulate_cpf_enrichment(generate_fake_cpf()),
                "card_analysis": simulate_credit_card_analysis(generate_credit_card())
            }
            
            filename = f"cybersec_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=4, ensure_ascii=False)
            log(f"Relatório exportado com sucesso para: {filename}", "SUCCESS")
        else:
            log("Opção inválida. Tente novamente.", "WARNING")

if __name__ == "__main__":
    main()