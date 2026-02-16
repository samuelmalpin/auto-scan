#!/usr/bin/env python3
from __future__ import annotations
"""Auto Scan terminal (semi-GUI) basé sur Nmap.

Ce script exécute un workflow orienté pentest local:
1) Choix du mode de démarrage (interface détectée ou CIDR manuel)
2) Découverte rapide des hôtes du réseau
3) Dashboard interactif pour lancer des analyses par hôte ou réseau

Le rendu utilise `rich` si disponible, avec fallback texte sinon.
"""

import re
import json
import html
import shutil
import subprocess
import tempfile
import importlib
import ipaddress
import platform
import queue
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

if platform.system().lower() == "windows":
    import ctypes
    import msvcrt
else:
    import select
    import termios
    import tty

try:
    rich_console = importlib.import_module("rich.console")
    rich_panel = importlib.import_module("rich.panel")
    rich_prompt = importlib.import_module("rich.prompt")
    rich_table = importlib.import_module("rich.table")
    rich_text = importlib.import_module("rich.text")
    rich_live = importlib.import_module("rich.live")
    rich_layout = importlib.import_module("rich.layout")

    Console = rich_console.Console
    Panel = rich_panel.Panel
    Prompt = rich_prompt.Prompt
    Table = rich_table.Table
    Text = rich_text.Text
    Live = rich_live.Live
    Layout = rich_layout.Layout
    RICH_AVAILABLE = True
except Exception:
    Console = Any
    Panel = Any
    Prompt = Any
    Table = Any
    Text = Any
    Live = Any
    Layout = Any
    RICH_AVAILABLE = False


@dataclass
class NetworkInterface:
    """Représente une interface réseau IPv4 détectée."""

    name: str
    ipv4: str
    netmask: str
    is_wifi: bool = False
    active_ipv4: bool = True


@dataclass
class HostAnalysis:
    """État d'analyse cumulatif d'un hôte pendant la session."""

    open_ports: int = 0
    udp_open: bool = False
    windows_os: bool = False
    vuln_count: int = 0
    findings: list[str] | None = None

    def ensure_findings(self) -> list[str]:
        if self.findings is None:
            self.findings = []
        return self.findings


class TerminalUI:
    """Abstraction UI terminal (rich si dispo, sinon mode texte simple)."""

    def __init__(self) -> None:
        self.console = Console() if RICH_AVAILABLE else None

    def clear(self) -> None:
        if RICH_AVAILABLE:
            self.console.clear()
        else:
            print("\n" * 3)

    def title(self, text: str) -> None:
        if RICH_AVAILABLE:
            self.console.print(Panel.fit(f"[bold cyan]{text}[/bold cyan]"))
        else:
            print("=" * 60)
            print(text)
            print("=" * 60)

    def banner(self) -> None:
        if RICH_AVAILABLE:
            art = (
                "[bold green]"
                "   █████╗ ██╗   ██╗████████╗ ██████╗     ███████╗ ██████╗ █████╗ ███╗   ██╗\n"
                "  ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔════╝██╔════╝██╔══██╗████╗  ██║\n"
                "  ███████║██║   ██║   ██║   ██║   ██║    ███████╗██║     ███████║██╔██╗ ██║\n"
                "  ██╔══██║██║   ██║   ██║   ██║   ██║    ╚════██║██║     ██╔══██║██║╚██╗██║\n"
                "  ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ███████║╚██████╗██║  ██║██║ ╚████║\n"
                "  ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n"
                "[/bold green]"
            )
            self.console.print(Panel(art, title="[green]Terminal Dashboard[/green]", border_style="green"))
        else:
            print("=" * 76)
            print("AUTO SCAN TERMINAL DASHBOARD")
            print("=" * 76)

    def table_interfaces(self, interfaces: list[NetworkInterface]) -> None:
        if RICH_AVAILABLE:
            table = Table(title="Interfaces détectées", header_style="bold green")
            table.add_column("#", style="cyan", width=4)
            table.add_column("Nom", style="white")
            table.add_column("Type", style="magenta", width=10)
            table.add_column("État", style="cyan", width=12)
            table.add_column("IPv4", style="green")
            table.add_column("Masque", style="yellow")
            for idx, iface in enumerate(interfaces, start=1):
                iface_type = "Wi-Fi" if iface.is_wifi else "LAN"
                state = "Actif" if iface.active_ipv4 else "Sans IPv4"
                table.add_row(str(idx), iface.name, iface_type, state, iface.ipv4, iface.netmask)
            self.console.print(table)
        else:
            print("Interfaces détectées:")
            for idx, iface in enumerate(interfaces, start=1):
                iface_type = "Wi-Fi" if iface.is_wifi else "LAN"
                state = "Actif" if iface.active_ipv4 else "Sans IPv4"
                print(f"  {idx}. [{iface_type}] [{state}] {iface.name} - {iface.ipv4} / {iface.netmask}")

    def info(self, text: str) -> None:
        if RICH_AVAILABLE:
            self.console.print(f"[cyan]ℹ[/cyan] {text}")
        else:
            print(f"[i] {text}")

    def ok(self, text: str) -> None:
        if RICH_AVAILABLE:
            self.console.print(f"[green]✔[/green] {text}")
        else:
            print(f"[OK] {text}")

    def warn(self, text: str) -> None:
        if RICH_AVAILABLE:
            self.console.print(f"[yellow]⚠[/yellow] {text}")
        else:
            print(f"[!] {text}")

    def error(self, text: str) -> None:
        if RICH_AVAILABLE:
            self.console.print(f"[red]✖[/red] {text}")
        else:
            print(f"[ERR] {text}")

    def ask(self, prompt_text: str, default: str | None = None) -> str:
        if RICH_AVAILABLE:
            return Prompt.ask(prompt_text, default=default or "").strip()
        raw = input(f"{prompt_text}{f' [{default}]' if default else ''}: ").strip()
        if not raw and default is not None:
            return default
        return raw

    def confirm(self, prompt_text: str, default_yes: bool = False) -> bool:
        suffix = "[Y/n]" if default_yes else "[y/N]"
        value = self.ask(f"{prompt_text} {suffix}").lower()
        if not value:
            return default_yes
        return value in {"y", "yes", "o", "oui"}

    def wait(self) -> None:
        _ = self.ask("Entrée pour continuer")


class AutoScanTUI:
    """Orchestrateur principal du scanner et du dashboard interactif.

    Responsabilités:
    - Détecter les interfaces et le réseau cible.
    - Piloter les scans Nmap (découverte, ports, fingerprint, vuln, profils).
    - Maintenir l'état session (logs, scores, tags, exports).
    - Afficher et gérer la navigation clavier dans le dashboard.
    """

    def __init__(self) -> None:
        self.ui = TerminalUI()
        self.last_target = "192.168.1.0/24"
        self.output_dir = Path.home() / "nmap_scans"
        self.temp_dir = Path(tempfile.gettempdir())
        self.result_xml = self.temp_dir / "scan_result.xml"
        self.result_txt = self.temp_dir / "scan_result.txt"
        self.discovery_oa_base = self.temp_dir / "host_max_discovery"
        self.selected_interface: NetworkInterface | None = None
        self.last_discovery_count = 0
        self.host_analyses: dict[str, HostAnalysis] = {}
        self.host_tags: dict[str, set[str]] = {}
        self.discovery_logs: list[str] = []
        self.session_started_at = datetime.now()
        self.session_mode = ""
        self.session_network = ""
        self.session_interface = ""

        self.post_actions: list[tuple[str, str]] = [
            ("ports", "Découverte Ports"),
            ("fingerprint", "Fingerprinting OS/Services"),
            ("vulns", "Vulnérabilités"),
            ("score", "Catégorisation automatique (Score 0-100)"),
            ("tags", "Tags d'actifs"),
            ("profiles", "Profils de scan"),
            ("export", "Export rapport (JSON/HTML)"),
            ("extra", "Scan supplémentaires"),
        ]
        self.asset_tag_presets: list[tuple[str, str]] = [
            ("serveur", "Serveur"),
            ("poste", "Poste"),
            ("iot", "IoT"),
            ("critical", "Critique"),
            ("dmz", "DMZ"),
            ("externe", "Exposé Internet"),
        ]
        self.scan_profiles: list[tuple[str, str, list[str], str]] = [
            ("quick", "Rapide", ["-Pn", "-sS", "--top-ports", "100", "-T4"], "Top 100 ports"),
            ("deep", "Complet", ["-Pn", "-sS", "-sV", "-sC", "-O", "--top-ports", "1000", "-T4"], "Fingerprint large"),
            ("web", "Web", ["-Pn", "-sS", "-sV", "-p", "80,443,8080,8443", "--script", "http-title,http-headers,http-methods"], "Cibles web"),
            ("windows", "Windows/AD", ["-Pn", "-sS", "-sV", "-p", "53,88,135,139,389,445,464,636,3268,3389", "--script", "smb-os-discovery"], "Services AD"),
            ("iot", "IoT", ["-Pn", "-sS", "-sV", "--top-ports", "200", "--script", "banner"], "Bannière IoT"),
        ]
        self.vuln_advanced_scripts: list[str] = [
            "vuln",
            "smb-vuln*",
            "http-vuln*",
            "ssl-heartbleed",
            "ssl-poodle",
            "ssl-ccs-injection",
            "rdp-vuln-ms12-020",
            "ftp-vsftpd-backdoor",
            "sshv1",
        ]
        self.vuln_scan_modes: list[tuple[str, str, str]] = [
            ("light", "Vuln léger", "Rapide, scripts vuln uniquement"),
            ("advanced", "Vuln avancé", "Set ciblé SMB/HTTP/SSL/RDP/FTP/SSH"),
            ("full", "Vuln full", "Plus large, plus lent"),
        ]
        self.current_vuln_mode = "advanced"
        self._win_key_state: dict[int, bool] = {}
        self._win_vk_map: dict[int, str] = {
            0x26: "UP",
            0x28: "DOWN",
            0x09: "TAB",
            0x0D: "ENTER",
            0x20: "SPACE",
            0x55: "U",
            0x4E: "N",
            0x4A: "J",
            0x4B: "K",
            0x51: "Q",
        }

    def _format_duration(self, seconds: float) -> str:
        total = max(0, int(seconds))
        mins, secs = divmod(total, 60)
        hours, mins = divmod(mins, 60)
        if hours > 0:
            return f"{hours:02d}:{mins:02d}:{secs:02d}"
        return f"{mins:02d}:{secs:02d}"

    def _estimate_action_duration(self, action_id: str, targets: list[str]) -> float:
        if not targets:
            return 0.0

        base_per_host = 30.0
        if action_id == "ports":
            base_per_host = 25.0
        elif action_id == "fingerprint":
            base_per_host = 95.0
        elif action_id == "vulns":
            base_per_host = 300.0
        elif action_id == "score":
            base_per_host = 3.0

        total = 0.0
        for host in targets:
            analysis = self._analysis_for_host(host)
            host_factor = 1.0 + min(analysis.open_ports, 100) / 250.0
            if action_id == "vulns" and analysis.vuln_count > 0:
                host_factor += 0.2
            total += base_per_host * host_factor

        total += len(targets) * 2.0
        return total

    def _estimate_additional_duration(
        self,
        scan_mode: str,
        targets: list[str],
        port_start: int,
        port_end: int,
        extra_ports: list[int],
    ) -> float:
        if not targets:
            return 0.0

        port_count = max(1, (port_end - port_start + 1) + len(extra_ports))
        if scan_mode == "tcp_udp":
            unit = 0.22
        elif scan_mode == "udp":
            unit = 0.18
        else:
            unit = 0.10

        per_host = 8.0 + (port_count * unit)
        return (per_host * len(targets)) + (len(targets) * 2.0)

    def _estimate_profile_duration(self, profile_id: str, host_count: int) -> float:
        if host_count <= 0:
            host_count = 1

        per_host = 30.0
        if profile_id == "quick":
            per_host = 12.0
        elif profile_id == "deep":
            per_host = 170.0
        elif profile_id == "web":
            per_host = 70.0
        elif profile_id == "windows":
            per_host = 80.0
        elif profile_id == "iot":
            per_host = 55.0

        return (per_host * host_count) + (host_count * 2.0)

    def _run_command_with_ticks(self, cmd: list[str], on_tick: Callable[[], None] | None = None) -> subprocess.CompletedProcess[str]:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        while process.poll() is None:
            if on_tick is not None:
                on_tick()
            time.sleep(0.12)

        stdout, stderr = process.communicate()
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)

    def _ingest_network_scan_output(self, label: str, target_network: str, output: str) -> tuple[int, int]:
        host_ports: dict[str, list[tuple[str, str]]] = {}
        host_extras: dict[str, list[str]] = {}
        current_host = ""

        for raw_line in output.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("Nmap scan report for "):
                current_host = stripped.replace("Nmap scan report for ", "", 1).strip()
                host_ports.setdefault(current_host, [])
                host_extras.setdefault(current_host, [])
                continue

            open_match = re.match(r"^(\d+)/(tcp|udp)\s+open", stripped)
            if open_match and current_host:
                host_ports.setdefault(current_host, []).append((open_match.group(1), open_match.group(2)))
                continue

            if current_host and (
                stripped.startswith("Running:")
                or stripped.startswith("OS details:")
                or stripped.startswith("Service Info:")
                or "VULNERABLE" in stripped
                or "CVE-" in stripped
            ):
                host_extras.setdefault(current_host, []).append(stripped)

        touched_hosts = 0
        total_open = 0
        for host, ports in host_ports.items():
            touched_hosts += 1
            analysis = self._analysis_for_host(host)
            findings = analysis.ensure_findings()

            if ports:
                total_open += len(ports)
                analysis.open_ports = max(analysis.open_ports, len(ports))
                if any(proto == "udp" for _, proto in ports):
                    analysis.udp_open = True
                findings.append(f"[{label}] Réseau {target_network}: {len(ports)} ports ouverts")
                findings.append(f"[{label}] Exemples: {', '.join(f'{p}/{proto}' for p, proto in ports[:20])}")
            else:
                findings.append(f"[{label}] Réseau {target_network}: aucun port ouvert détecté")

            for line in host_extras.get(host, [])[:12]:
                findings.append(f"[{label}] {line}")
                if "windows" in line.lower():
                    analysis.windows_os = True
                if "VULNERABLE" in line or "CVE-" in line:
                    analysis.vuln_count += 1

        return touched_hosts, total_open

    def _is_wifi_name(self, name: str) -> bool:
        lowered = name.lower()
        wifi_keywords = ["wifi", "wi-fi", "wireless", "wlan", "sans fil", "802.11", "wl"]
        return any(keyword in lowered for keyword in wifi_keywords)

    def _windows_wifi_names(self) -> set[str]:
        names: set[str] = set()
        try:
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, check=False)
            if result.returncode != 0:
                return names

            for line in result.stdout.splitlines():
                lowered = line.lower()
                if ("name" in lowered or "nom" in lowered) and ":" in line:
                    key, value = line.split(":", 1)
                    key_l = key.strip().lower()
                    if key_l in {"name", "nom"}:
                        candidate = value.strip()
                        if candidate:
                            names.add(candidate)
        except Exception:
            return names
        return names

    def _read_key_nonblocking(self) -> str | None:
        if platform.system().lower() == "windows":
            for vk, key_name in self._win_vk_map.items():
                state = ctypes.windll.user32.GetAsyncKeyState(vk)
                is_pressed = (state & 0x8000) != 0
                was_pressed = self._win_key_state.get(vk, False)
                self._win_key_state[vk] = is_pressed
                if is_pressed and not was_pressed:
                    return key_name

            if not msvcrt.kbhit():
                return None
            ch = msvcrt.getch()
            if ch in (b"\x00", b"\xe0"):
                nxt = msvcrt.getch()
                if nxt == b"H":
                    return "UP"
                if nxt == b"P":
                    return "DOWN"
                return None
            if ch == b"\r":
                return "ENTER"
            if ch == b"\t":
                return "TAB"
            if ch == b" ":
                return "SPACE"
            if ch in (b"u", b"U"):
                return "U"
            if ch in (b"n", b"N"):
                return "N"
            if ch in (b"j", b"J"):
                return "J"
            if ch in (b"k", b"K"):
                return "K"
            if ch in (b"q", b"Q"):
                return "Q"
            return None

        dr, _, _ = select.select([sys.stdin], [], [], 0)
        if not dr:
            return None
        first = sys.stdin.read(1)
        if first == "\n":
            return "ENTER"
        if first == "\t":
            return "TAB"
        if first == " ":
            return "SPACE"
        if first in {"u", "U"}:
            return "U"
        if first in {"n", "N"}:
            return "N"
        if first in {"j", "J"}:
            return "J"
        if first in {"k", "K"}:
            return "K"
        if first in {"q", "Q"}:
            return "Q"
        if first != "\x1b":
            return None
        seq = sys.stdin.read(2)
        if seq == "[A":
            return "UP"
        if seq == "[B":
            return "DOWN"
        return None

    def _flush_input_buffer(self) -> None:
        if platform.system().lower() == "windows":
            while msvcrt.kbhit():
                _ = msvcrt.getch()
            for vk in self._win_vk_map:
                self._win_key_state[vk] = False
            return

        try:
            while True:
                dr, _, _ = select.select([sys.stdin], [], [], 0)
                if not dr:
                    break
                _ = sys.stdin.read(1)
        except Exception:
            return

    def _analysis_for_host(self, host: str) -> HostAnalysis:
        if host not in self.host_analyses:
            self.host_analyses[host] = HostAnalysis()
        return self.host_analyses[host]

    def _tags_for_host(self, host: str) -> set[str]:
        if host not in self.host_tags:
            self.host_tags[host] = set()
        return self.host_tags[host]

    def _toggle_tag_for_targets(self, targets: list[str], tag: str) -> None:
        for host in targets:
            tags = self._tags_for_host(host)
            if tag in tags:
                tags.remove(tag)
            else:
                tags.add(tag)

    def _clear_tags_for_targets(self, targets: list[str]) -> None:
        for host in targets:
            self._tags_for_host(host).clear()

    def _score_host(self, host: str) -> tuple[int, str]:
        analysis = self._analysis_for_host(host)
        score = 0
        reasons: list[str] = []

        if analysis.windows_os:
            score += 30
            reasons.append("OS Windows: +30")
        if analysis.open_ports > 50:
            score += 40
            reasons.append(">50 ports: +40")
        if analysis.vuln_count > 0:
            score += 50
            reasons.append("Vulns trouvées: +50")
        if analysis.udp_open:
            score += 15
            reasons.append("UDP ouvert: +15")

        if score >= 70:
            level = "HIGH"
        elif score >= 40:
            level = "MEDIUM"
        else:
            level = "LOW"

        findings = analysis.ensure_findings()
        findings.append(f"[Score] {score}/100 -> {level}")
        if reasons:
            findings.append("[Score] " + " | ".join(reasons))
        else:
            findings.append("[Score] Pas assez de signaux collectés.")

        return score, level

    def _run_action_on_host(
        self,
        action_id: str,
        host: str,
        on_tick: Callable[[], None] | None = None,
        vuln_mode: str | None = None,
    ) -> None:
        """Exécute une action d'analyse ciblée sur un hôte.

        Args:
            action_id: Type d'action (`ports`, `fingerprint`, `vulns`, `score`).
            host: Hôte cible.
            on_tick: Callback rafraîchissement UI pendant l'exécution.
            vuln_mode: Mode vulnérabilité optionnel (`light`, `advanced`, `full`).
        """
        analysis = self._analysis_for_host(host)
        findings = analysis.ensure_findings()

        if action_id == "ports":
            cmd = ["nmap", "-Pn", "-sS", "--top-ports", "1000", host]
            completed = self._run_command_with_ticks(cmd, on_tick=on_tick)
            self.discovery_logs.append(f"Action Ports sur {host}: rc={completed.returncode}")
            if completed.returncode != 0:
                findings.append(f"[Ports] Échec scan: {completed.stderr.strip() or 'erreur inconnue'}")
                return

            matches = re.findall(r"^(\d+)/(tcp|udp)\s+open", completed.stdout, flags=re.MULTILINE)
            analysis.open_ports = len(matches)
            analysis.udp_open = any(proto == "udp" for _, proto in matches)
            if matches:
                first_ports = ", ".join(f"{port}/{proto}" for port, proto in matches[:20])
                findings.append(f"[Ports] {analysis.open_ports} ports ouverts")
                findings.append(f"[Ports] {first_ports}")
            else:
                findings.append("[Ports] Aucun port ouvert détecté")
            return

        if action_id == "fingerprint":
            cmd = ["nmap", "-Pn", "-O", "-sV", host]
            completed = self._run_command_with_ticks(cmd, on_tick=on_tick)
            self.discovery_logs.append(f"Action Fingerprint sur {host}: rc={completed.returncode}")
            if completed.returncode != 0:
                findings.append(f"[Fingerprint] Échec scan: {completed.stderr.strip() or 'erreur inconnue'}")
                return

            out = completed.stdout
            analysis.windows_os = "windows" in out.lower()
            fp_lines = []
            for line in out.splitlines():
                if line.startswith("Running:") or line.startswith("OS details:") or line.startswith("Service Info:"):
                    fp_lines.append(line.strip())
            if fp_lines:
                findings.extend(f"[Fingerprint] {line}" for line in fp_lines[:8])
            else:
                findings.append("[Fingerprint] Empreinte OS/services non déterminée")
            return

        if action_id == "vulns":
            mode = vuln_mode or self.current_vuln_mode
            if mode == "light":
                scripts_arg = "vuln"
                timeout_value = "15s"
                timing_value = "-T4"
            elif mode == "full":
                scripts_arg = "vuln,smb-vuln*,http-vuln*,ssl-*,rdp-vuln*,ftp-*,ssh-*"
                timeout_value = "45s"
                timing_value = "-T3"
            else:
                scripts_arg = ",".join(self.vuln_advanced_scripts)
                timeout_value = "30s"
                timing_value = "-T4"

            advanced_cmd = [
                "nmap",
                "-Pn",
                "-sV",
                "--script",
                scripts_arg,
                "--script-timeout",
                timeout_value,
                "--max-retries",
                "1",
                timing_value,
                host,
            ]
            completed = self._run_command_with_ticks(advanced_cmd, on_tick=on_tick)
            self.discovery_logs.append(f"Action Vulns ({mode}) sur {host}: rc={completed.returncode}")

            if completed.returncode != 0:
                fallback_cmd = ["nmap", "-Pn", "--script", "vuln", host]
                fallback = self._run_command_with_ticks(fallback_cmd, on_tick=on_tick)
                self.discovery_logs.append(f"Fallback Vulns (vuln) sur {host}: rc={fallback.returncode}")
                if fallback.returncode != 0:
                    findings.append(
                        f"[Vulns+] Échec scan avancé/fallback: {fallback.stderr.strip() or completed.stderr.strip() or 'erreur inconnue'}"
                    )
                    return
                completed = fallback
                findings.append("[Vulns] Fallback utilisé: --script vuln")

            vuln_raw = [line.strip() for line in completed.stdout.splitlines() if "VULNERABLE" in line or "CVE-" in line]
            vuln_unique = list(dict.fromkeys(vuln_raw))
            analysis.vuln_count = max(analysis.vuln_count, len(vuln_unique))

            findings.append(f"[Vulns:{mode}] Scripts: {scripts_arg}")
            if vuln_unique:
                findings.append(f"[Vulns:{mode}] {len(vuln_unique)} indicateurs trouvés")
                findings.extend(f"[Vulns:{mode}] {line}" for line in vuln_unique[:15])
            else:
                findings.append(f"[Vulns:{mode}] Aucun indicateur vulnérabilité détecté")
            return

        if action_id == "score":
            score, level = self._score_host(host)
            self.discovery_logs.append(f"Action Score sur {host}: {score}/100 {level}")

    def _prompt_additional_scan_params(self, scan_label: str) -> tuple[int, int, list[int]] | None:
        self.ui.info(f"Configuration {scan_label}")
        start_raw = self.ui.ask("Port de début", default="1")
        end_raw = self.ui.ask("Port de fin", default="1024")
        extra_raw = self.ui.ask("Ports spécifiques hors plage (optionnel, ex: 3389,8080)", default="")

        try:
            port_start = int(start_raw)
            port_end = int(end_raw)
        except ValueError:
            self.ui.warn("Début/fin invalides (entiers attendus).")
            return None

        if not (1 <= port_start <= 65535 and 1 <= port_end <= 65535):
            self.ui.warn("Les ports doivent être entre 1 et 65535.")
            return None
        if port_start > port_end:
            self.ui.warn("Le port de début doit être <= port de fin.")
            return None

        extra_ports: list[int] = []
        if extra_raw.strip():
            for token in extra_raw.split(","):
                token = token.strip()
                if not token:
                    continue
                if not token.isdigit():
                    self.ui.warn(f"Port invalide: {token}")
                    return None
                port_value = int(token)
                if not (1 <= port_value <= 65535):
                    self.ui.warn(f"Port hors plage: {port_value}")
                    return None
                if port_value < port_start or port_value > port_end:
                    extra_ports.append(port_value)

        extra_ports = sorted(set(extra_ports))
        return port_start, port_end, extra_ports

    def _build_ports_spec(self, port_start: int, port_end: int, extra_ports: list[int]) -> str:
        parts = [f"{port_start}-{port_end}"]
        if extra_ports:
            parts.extend(str(port) for port in extra_ports)
        return ",".join(parts)

    def _run_additional_scan_on_network(
        self,
        target_network: str,
        scan_mode: str,
        port_start: int,
        port_end: int,
        extra_ports: list[int],
        on_tick: Callable[[], None] | None = None,
    ) -> None:
        """Lance un scan réseau additionnel (TCP, UDP ou mixte) sur une plage de ports."""
        ports_spec = self._build_ports_spec(port_start, port_end, extra_ports)
        if scan_mode == "tcp_udp":
            cmd = ["nmap", "-Pn", "-sS", "-sU", "-p", ports_spec, target_network]
            label = "TCP/UDP"
        elif scan_mode == "tcp":
            cmd = ["nmap", "-Pn", "-sS", "-p", ports_spec, target_network]
            label = "TCP"
        else:
            cmd = ["nmap", "-Pn", "-sU", "-p", ports_spec, target_network]
            label = "UDP"

        completed = self._run_command_with_ticks(cmd, on_tick=on_tick)
        self.discovery_logs.append(f"Action Scan {label} sur réseau {target_network}: rc={completed.returncode}")

        if completed.returncode != 0:
            self.discovery_logs.append(f"Scan {label} réseau échoué: {completed.stderr.strip() or 'erreur inconnue'}")
            return

        touched_hosts, total_open = self._ingest_network_scan_output(f"Scan {label}", target_network, completed.stdout)

        if total_open == 0:
            self.discovery_logs.append(f"Scan {label}: aucun port ouvert détecté sur {target_network}")
        else:
            self.discovery_logs.append(
                f"Scan {label}: {total_open} ports ouverts détectés sur le réseau {target_network} ({touched_hosts} hôte(s))"
            )

    def _run_profile_scan_on_network(
        self,
        target_network: str,
        profile_id: str,
        on_tick: Callable[[], None] | None = None,
    ) -> None:
        """Exécute un profil de scan prédéfini sur tout le réseau cible."""
        profile = next((p for p in self.scan_profiles if p[0] == profile_id), None)
        if profile is None:
            self.discovery_logs.append(f"Profil inconnu: {profile_id}")
            return

        _, profile_label, profile_args, _ = profile
        cmd = ["nmap", *profile_args, target_network]
        completed = self._run_command_with_ticks(cmd, on_tick=on_tick)
        self.discovery_logs.append(f"Action Profil {profile_label} sur réseau {target_network}: rc={completed.returncode}")

        if completed.returncode != 0:
            self.discovery_logs.append(f"Profil {profile_label} échoué: {completed.stderr.strip() or 'erreur inconnue'}")
            return

        touched_hosts, total_open = self._ingest_network_scan_output(f"Profil {profile_label}", target_network, completed.stdout)
        self.discovery_logs.append(
            f"Profil {profile_label}: {total_open} ports ouverts détectés sur {touched_hosts} hôte(s)"
        )

    def _export_session_reports(self, hosts: list[str]) -> tuple[Path, Path]:
        """Exporte l'état courant en rapports JSON et HTML.

        Returns:
            Tuple (chemin_json, chemin_html)
        """
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path = self.output_dir / f"session_report_{stamp}.json"
        html_path = self.output_dir / f"session_report_{stamp}.html"

        ordered_hosts = hosts[:] if hosts else sorted(self.host_analyses.keys())
        payload_hosts: list[dict[str, Any]] = []
        for host in ordered_hosts:
            analysis = self._analysis_for_host(host)
            score = 0
            if analysis.windows_os:
                score += 30
            if analysis.open_ports > 50:
                score += 40
            if analysis.vuln_count > 0:
                score += 50
            if analysis.udp_open:
                score += 15

            if score >= 70:
                level = "HIGH"
            elif score >= 40:
                level = "MEDIUM"
            else:
                level = "LOW"
            payload_hosts.append(
                {
                    "host": host,
                    "tags": sorted(self._tags_for_host(host)),
                    "open_ports": analysis.open_ports,
                    "udp_open": analysis.udp_open,
                    "windows_os": analysis.windows_os,
                    "vuln_count": analysis.vuln_count,
                    "score": score,
                    "risk_level": level,
                    "findings": analysis.ensure_findings(),
                }
            )

        report = {
            "generated_at": datetime.now().isoformat(),
            "session_started_at": self.session_started_at.isoformat(),
            "session_mode": self.session_mode,
            "session_network": self.session_network,
            "session_interface": self.session_interface,
            "total_hosts": len(payload_hosts),
            "hosts": payload_hosts,
        }
        json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

        rows = []
        for item in payload_hosts:
            rows.append(
                "<tr>"
                f"<td>{html.escape(item['host'])}</td>"
                f"<td>{html.escape(', '.join(item['tags']) if item['tags'] else '-')}</td>"
                f"<td>{item['open_ports']}</td>"
                f"<td>{'oui' if item['udp_open'] else 'non'}</td>"
                f"<td>{'oui' if item['windows_os'] else 'non'}</td>"
                f"<td>{item['vuln_count']}</td>"
                f"<td>{item['score']} ({item['risk_level']})</td>"
                f"<td><pre>{html.escape(chr(10).join(item['findings'][-20:]))}</pre></td>"
                "</tr>"
            )

        html_doc = (
            "<html><head><meta charset='utf-8'><title>Auto Scan Report</title>"
            "<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0b0f10;color:#e5e7eb;padding:20px;}"
            "table{width:100%;border-collapse:collapse;background:#111827;}th,td{border:1px solid #374151;padding:8px;vertical-align:top;}"
            "th{background:#1f2937;}pre{white-space:pre-wrap;margin:0;}</style></head><body>"
            f"<h1>Auto Scan Report</h1><p>Réseau: {html.escape(self.session_network or self.last_target)}</p>"
            f"<p>Mode: {html.escape(self.session_mode or 'unknown')} | Interface: {html.escape(self.session_interface or 'N/A')}</p>"
            "<table><thead><tr><th>Host</th><th>Tags</th><th>Open Ports</th><th>UDP Open</th><th>Windows</th><th>Vulns</th><th>Score</th><th>Findings</th></tr></thead><tbody>"
            + "".join(rows)
            + "</tbody></table></body></html>"
        )
        html_path.write_text(html_doc, encoding="utf-8")
        return json_path, html_path

    def _render_discovery_layout(
        self,
        network: ipaddress.IPv4Network,
        logs: list[str],
        hosts: list[str],
        selected_idx: int,
        running: bool,
        selected_hosts: set[str] | None = None,
    ) -> Any:
        selected_hosts = selected_hosts or set()
        status = "EN COURS" if running else "TERMINÉ"

        left_text = "\n".join(logs[-22:]) if logs else "Initialisation du scan..."
        left_panel = Panel(
            left_text,
            title=f"[bold cyan]Scan hôtes {network} ({status})[/bold cyan]",
            border_style="cyan",
        )

        table = Table(title="Hôtes détectés", header_style="bold green", expand=True)
        table.add_column("#", width=4, style="cyan")
        table.add_column("Hôte", style="green")

        if not hosts:
            table.add_row("-", "Aucun hôte pour l'instant")
        else:
            for idx, host in enumerate(hosts):
                is_marked = host in selected_hosts
                marker = "▶" if idx == selected_idx else " "
                marker += "*" if is_marked else " "
                style = "bold white on dark_green" if idx == selected_idx else "white"
                table.add_row(f"{marker}{idx + 1}", Text(host, style=style))

        right_panel = Panel(
            table,
            title="[bold green]Navigation[/bold green]",
            subtitle="↑/↓ pour naviguer | Espace pour marquer",
            border_style="green",
        )

        layout = Layout()
        layout.split_row(
            Layout(left_panel, ratio=1),
            Layout(right_panel, ratio=1),
        )
        return layout

    def _render_post_scan_layout(
        self,
        hosts: list[str],
        selected_hosts: set[str],
        host_idx: int,
        focus: str,
        action_idx: int,
        log_scroll: int,
        scan_running: bool = False,
        scan_action_label: str = "",
        scan_current_host: str = "",
        scan_done: int = 0,
        scan_total: int = 0,
        scan_elapsed_sec: float = 0.0,
        scan_estimated_sec: float = 0.0,
        spinner_frame: str = "⠋",
        extra_menu_active: bool = False,
        extra_menu_idx: int = 0,
        profile_menu_active: bool = False,
        profile_menu_idx: int = 0,
        vuln_menu_active: bool = False,
        vuln_menu_idx: int = 0,
        tags_menu_active: bool = False,
        tags_menu_idx: int = 0,
        detail_scroll: int = 0,
    ) -> Any:
        def build_progress_bar(progress_ratio: float, width: int = 24) -> str:
            ratio = max(0.0, min(1.0, progress_ratio))
            if ratio <= 0:
                return "[dim]" + ("░" * width) + "[/dim]"
            filled = int(ratio * width)
            empty = width - filled
            return f"[bold green]{'█' * filled}[/bold green][dim]{'░' * empty}[/dim]"

        host = hosts[host_idx] if hosts else "Aucun"
        action_lines: list[str] = ["[bold green]✓ Scan découverte terminé et complet[/bold green]", ""]
        if scan_running:
            host_ratio = (scan_done / scan_total) if scan_total > 0 else 0.0
            time_ratio = (scan_elapsed_sec / scan_estimated_sec) if scan_estimated_sec > 0 else host_ratio
            progress_ratio = max(host_ratio, min(0.99, time_ratio))
            progress_percent = int(progress_ratio * 100)
            remaining_sec = max(0.0, scan_estimated_sec - scan_elapsed_sec) if scan_estimated_sec > 0 else 0.0

            action_lines.append(f"[bold yellow]{spinner_frame} EN COURS[/bold yellow] {scan_action_label}")
            action_lines.append(f"Progression: [bold]{scan_done}/{scan_total}[/bold] ({progress_percent}%)")
            action_lines.append(build_progress_bar(progress_ratio))
            if scan_estimated_sec > 0:
                action_lines.append(
                    f"Temps: écoulé [bold]{self._format_duration(scan_elapsed_sec)}[/bold] | restant ~[bold]{self._format_duration(remaining_sec)}[/bold]"
                )
            if scan_current_host:
                action_lines.append(f"Hôte courant: [bold cyan]{scan_current_host}[/bold cyan]")
            action_lines.append("")
        elif scan_total > 0:
            action_lines.append(f"[bold green]✅ Dernière action terminée[/bold green] : {scan_action_label}")
            action_lines.append(f"Résultat: [bold]{scan_done}/{scan_total}[/bold]")
            action_lines.append(build_progress_bar(1.0))
            if scan_estimated_sec > 0:
                action_lines.append(
                    f"Temps final: [bold]{self._format_duration(scan_elapsed_sec)}[/bold] (estimé {self._format_duration(scan_estimated_sec)})"
                )
            action_lines.append("")

        action_lines.append(f"Hôtes cochés: [bold]{len(selected_hosts)}[/bold]")
        action_lines.append(f"Mode vuln actuel: [bold]{self.current_vuln_mode}[/bold]")
        action_lines.append("")

        if tags_menu_active:
            action_lines.append("[bold magenta]Sous-menu: Tags d'actifs[/bold magenta]")
            tag_items = [f"Tag: {name}" for _, name in self.asset_tag_presets] + ["Effacer tags", "Retour"]
            for idx, item in enumerate(tag_items):
                marker = "▶" if idx == tags_menu_idx else " "
                if idx == tags_menu_idx:
                    action_lines.append(f"{marker} [bold cyan]{item}[/bold cyan]")
                else:
                    action_lines.append(f"{marker} {item}")
        elif vuln_menu_active:
            action_lines.append("[bold magenta]Sous-menu: Vulnérabilités[/bold magenta]")
            vuln_items = [f"{name} — {desc}" for _, name, desc in self.vuln_scan_modes] + ["Retour"]
            for idx, item in enumerate(vuln_items):
                marker = "▶" if idx == vuln_menu_idx else " "
                if idx == vuln_menu_idx:
                    action_lines.append(f"{marker} [bold cyan]{item}[/bold cyan]")
                else:
                    action_lines.append(f"{marker} {item}")
        elif profile_menu_active:
            action_lines.append("[bold magenta]Sous-menu: Profils de scan[/bold magenta]")
            profile_items = [f"{name} — {desc}" for _, name, _, desc in self.scan_profiles] + ["Retour"]
            for idx, item in enumerate(profile_items):
                marker = "▶" if idx == profile_menu_idx else " "
                if idx == profile_menu_idx:
                    action_lines.append(f"{marker} [bold cyan]{item}[/bold cyan]")
                else:
                    action_lines.append(f"{marker} {item}")
        elif extra_menu_active:
            extra_items = [
                "Scan TCP/UDP",
                "Scan TCP",
                "Scan UDP",
                "Retour",
            ]
            action_lines.append("[bold magenta]Sous-menu: Scan supplémentaires[/bold magenta]")
            for idx, item in enumerate(extra_items):
                marker = "▶" if idx == extra_menu_idx else " "
                if idx == extra_menu_idx:
                    action_lines.append(f"{marker} [bold cyan]{item}[/bold cyan]")
                else:
                    action_lines.append(f"{marker} {item}")
        else:
            for idx, (_, label) in enumerate(self.post_actions):
                marker = "▶" if idx == action_idx and focus == "left" else " "
                if idx == action_idx and focus == "left":
                    action_lines.append(f"{marker} [bold cyan]{label}[/bold cyan]")
                else:
                    action_lines.append(f"{marker} {label}")
        action_lines.append("")
        action_lines.append("[dim]TAB: basculer panneau[/dim]")
        action_lines.append("[dim]ENTER: exécuter option[/dim]")
        action_lines.append("[dim]Q: quitter ce dashboard[/dim]")
        left_top = Panel("\n".join(action_lines), title="[bold cyan]Options[/bold cyan]", border_style="cyan")

        host_table = Table(title="Hôtes", header_style="bold green", expand=True)
        host_table.add_column("#", style="cyan", width=5)
        host_table.add_column("Hôte", style="green")
        if not hosts:
            host_table.add_row("-", "Aucun hôte")
        else:
            for idx, item in enumerate(hosts):
                cursor = "▶" if idx == host_idx and focus == "right" else " "
                checked = "[x]" if item in selected_hosts else "[ ]"
                row_style = "bold white on dark_green" if idx == host_idx else "white"
                tags_preview = ", ".join(sorted(self._tags_for_host(item)))
                if tags_preview:
                    tags_preview = f" [{tags_preview}]"
                host_table.add_row(f"{cursor}{idx + 1}", Text(f"{checked} {item}{tags_preview}", style=row_style))

        right_top = Panel(
            host_table,
            title="[bold green]Sélection Hôtes[/bold green]",
            subtitle=f"↑/↓: naviguer | Espace: sélectionner | Focus: {focus.upper()}",
            border_style="green",
        )

        visible_height = 14
        max_scroll = max(0, len(self.discovery_logs) - visible_height)
        log_scroll = max(0, min(log_scroll, max_scroll))
        log_slice = self.discovery_logs[log_scroll : log_scroll + visible_height]
        left_bottom = Panel(
            "\n".join(log_slice) if log_slice else "Aucun log.",
            title=f"[bold magenta]Journal ({log_scroll + 1}/{max(1, len(self.discovery_logs))})[/bold magenta]",
            subtitle="U: monter | N: descendre",
            border_style="magenta",
        )

        details_lines = [f"Hôte actif: {host}"]
        if hosts:
            analysis = self._analysis_for_host(host)
            host_tags = sorted(self._tags_for_host(host))
            details_lines.append(f"Tags: {', '.join(host_tags) if host_tags else '-'}")
            details_lines.append(f"Ports ouverts: {analysis.open_ports}")
            details_lines.append(f"UDP ouvert: {'oui' if analysis.udp_open else 'non'}")
            details_lines.append(f"OS Windows: {'oui' if analysis.windows_os else 'non'}")
            details_lines.append(f"Vulns: {analysis.vuln_count}")
            details_lines.append("")
            findings = analysis.ensure_findings()
            if findings:
                details_lines.extend(findings)
            else:
                details_lines.append("Aucune analyse encore sur cet hôte.")

        details_visible_height = 14
        max_detail_scroll = max(0, len(details_lines) - details_visible_height)
        detail_scroll = max(0, min(detail_scroll, max_detail_scroll))
        details_slice = details_lines[detail_scroll : detail_scroll + details_visible_height]

        right_bottom = Panel(
            "\n".join(details_slice),
            title=f"[bold yellow]Détails Hôte ({detail_scroll + 1}/{max(1, len(details_lines))})[/bold yellow]",
            subtitle="K: monter | J: descendre",
            border_style="yellow",
        )

        layout = Layout()
        layout.split_column(
            Layout(name="top", ratio=1),
            Layout(name="bottom", ratio=1),
        )
        layout["top"].split_row(Layout(left_top, ratio=1), Layout(right_top, ratio=1))
        layout["bottom"].split_row(Layout(left_bottom, ratio=1), Layout(right_bottom, ratio=1))
        return layout

    def _post_scan_dashboard(self, hosts: list[str], selected_hosts: set[str], selected_idx: int) -> None:
        """Boucle principale du dashboard post-découverte.

        Navigation clavier:
        - TAB: changer le focus panneaux
        - ↑/↓: naviguer menus/hôtes
        - SPACE: cocher/décocher un hôte
        - ENTER: exécuter l'option active
        - U/N: scroll des logs
        - K/J: scroll du panneau détail
        - Q: quitter le dashboard
        """
        if not hosts or not RICH_AVAILABLE:
            return

        focus = "right"
        action_idx = 0
        host_idx = max(0, min(selected_idx, len(hosts) - 1))
        log_scroll = max(0, len(self.discovery_logs) - 14)
        scan_running = False
        scan_action_label = ""
        scan_current_host = ""
        scan_done = 0
        scan_total = 0
        scan_started_at = 0.0
        scan_elapsed_sec = 0.0
        scan_estimated_sec = 0.0
        spinner_frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner_idx = 0
        extra_menu_active = False
        extra_menu_idx = 0
        profile_menu_active = False
        profile_menu_idx = 0
        vuln_menu_active = False
        vuln_menu_idx = 0
        tags_menu_active = False
        tags_menu_idx = 0
        detail_scroll = 0

        def refresh_live() -> None:
            nonlocal spinner_idx, scan_elapsed_sec
            if scan_running:
                scan_elapsed_sec = time.time() - scan_started_at
                spinner_idx = (spinner_idx + 1) % len(spinner_frames)

            live.update(
                self._render_post_scan_layout(
                    hosts,
                    selected_hosts,
                    host_idx,
                    focus,
                    action_idx,
                    log_scroll,
                    scan_running,
                    scan_action_label,
                    scan_current_host,
                    scan_done,
                    scan_total,
                    scan_elapsed_sec,
                    scan_estimated_sec,
                    spinner_frames[spinner_idx],
                    extra_menu_active,
                    extra_menu_idx,
                    profile_menu_active,
                    profile_menu_idx,
                    vuln_menu_active,
                    vuln_menu_idx,
                    tags_menu_active,
                    tags_menu_idx,
                    detail_scroll,
                )
            )

        old_settings = None
        use_raw = platform.system().lower() != "windows" and sys.stdin.isatty()
        if use_raw:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            tty.setcbreak(fd)

        try:
            with Live(
                self._render_post_scan_layout(
                    hosts,
                    selected_hosts,
                    host_idx,
                    focus,
                    action_idx,
                    log_scroll,
                    scan_running,
                    scan_action_label,
                    scan_current_host,
                    scan_done,
                    scan_total,
                    scan_elapsed_sec,
                    scan_estimated_sec,
                    spinner_frames[spinner_idx],
                    extra_menu_active,
                    extra_menu_idx,
                    profile_menu_active,
                    profile_menu_idx,
                    vuln_menu_active,
                    vuln_menu_idx,
                    tags_menu_active,
                    tags_menu_idx,
                    detail_scroll,
                ),
                refresh_per_second=12,
                console=self.ui.console,
                screen=True,
            ) as live:
                while True:
                    def prompt_additional_params_safe(scan_label: str) -> tuple[int, int, list[int]] | None:
                        live.stop()
                        if use_raw and old_settings is not None:
                            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

                        self._flush_input_buffer()
                        params_local = self._prompt_additional_scan_params(scan_label)
                        self._flush_input_buffer()

                        if use_raw and old_settings is not None:
                            tty.setcbreak(fd)
                        live.start()
                        refresh_live()
                        return params_local

                    key = self._read_key_nonblocking()
                    if key == "TAB":
                        focus = "left" if focus == "right" else "right"
                    elif key == "Q":
                        break
                    elif key == "U":
                        log_scroll = max(0, log_scroll - 1)
                    elif key == "N":
                        log_scroll += 1
                    elif key == "K":
                        detail_scroll = max(0, detail_scroll - 1)
                    elif key == "J":
                        detail_scroll += 1
                    elif key == "UP":
                        if tags_menu_active:
                            tags_menu_idx = max(0, tags_menu_idx - 1)
                        elif vuln_menu_active:
                            vuln_menu_idx = max(0, vuln_menu_idx - 1)
                        elif profile_menu_active:
                            profile_menu_idx = max(0, profile_menu_idx - 1)
                        elif extra_menu_active:
                            extra_menu_idx = max(0, extra_menu_idx - 1)
                        elif focus == "right" and hosts:
                            host_idx = max(0, host_idx - 1)
                        elif focus == "left":
                            action_idx = max(0, action_idx - 1)
                    elif key == "DOWN":
                        if tags_menu_active:
                            tags_menu_idx = min(len(self.asset_tag_presets) + 1, tags_menu_idx + 1)
                        elif vuln_menu_active:
                            vuln_menu_idx = min(len(self.vuln_scan_modes), vuln_menu_idx + 1)
                        elif profile_menu_active:
                            profile_menu_idx = min(len(self.scan_profiles), profile_menu_idx + 1)
                        elif extra_menu_active:
                            extra_menu_idx = min(3, extra_menu_idx + 1)
                        elif focus == "right" and hosts:
                            host_idx = min(len(hosts) - 1, host_idx + 1)
                        elif focus == "left":
                            action_idx = min(len(self.post_actions) - 1, action_idx + 1)
                    elif key == "SPACE" and focus == "right" and hosts:
                        target = hosts[host_idx]
                        if target in selected_hosts:
                            selected_hosts.remove(target)
                        else:
                            selected_hosts.add(target)
                    elif key == "ENTER" and focus == "left":
                        if tags_menu_active:
                            targets = [hosts[host_idx]] if not selected_hosts else [h for h in hosts if h in selected_hosts]
                            if tags_menu_idx == len(self.asset_tag_presets):
                                self._clear_tags_for_targets(targets)
                                self.discovery_logs.append(f"Tags effacés sur {len(targets)} hôte(s)")
                            elif tags_menu_idx == len(self.asset_tag_presets) + 1:
                                tags_menu_active = False
                            else:
                                tag_key, tag_label = self.asset_tag_presets[tags_menu_idx]
                                self._toggle_tag_for_targets(targets, tag_key)
                                self.discovery_logs.append(f"Tag '{tag_label}' togglé sur {len(targets)} hôte(s)")
                        elif vuln_menu_active:
                            if vuln_menu_idx == len(self.vuln_scan_modes):
                                vuln_menu_active = False
                            else:
                                mode_id, mode_name, _ = self.vuln_scan_modes[vuln_menu_idx]
                                self.current_vuln_mode = mode_id
                                targets = [hosts[host_idx]] if not selected_hosts else [h for h in hosts if h in selected_hosts]
                                self.discovery_logs.append(
                                    f"Lancement Vulnérabilités ({mode_name}) sur {len(targets)} hôte(s)"
                                )
                                scan_running = True
                                scan_action_label = f"Vulnérabilités ({mode_name})"
                                scan_total = len(targets)
                                scan_done = 0
                                scan_current_host = ""
                                scan_estimated_sec = self._estimate_action_duration("vulns", targets)
                                if mode_id == "full":
                                    scan_estimated_sec *= 1.45
                                elif mode_id == "light":
                                    scan_estimated_sec *= 0.7
                                scan_started_at = time.time()
                                scan_elapsed_sec = 0.0
                                refresh_live()

                                for target_host in targets:
                                    scan_current_host = target_host
                                    refresh_live()
                                    self._run_action_on_host("vulns", target_host, on_tick=refresh_live, vuln_mode=mode_id)
                                    scan_done += 1
                                    refresh_live()

                                scan_running = False
                                scan_current_host = ""
                                scan_elapsed_sec = time.time() - scan_started_at
                                self.discovery_logs.append(f"Action Vulnérabilités ({mode_name}) terminée.")
                        elif profile_menu_active:
                            if profile_menu_idx == len(self.scan_profiles):
                                profile_menu_active = False
                            else:
                                profile_id, profile_name, _, _ = self.scan_profiles[profile_menu_idx]
                                self.discovery_logs.append(f"Lancement profil {profile_name} sur réseau {self.last_target}")
                                scan_running = True
                                scan_action_label = f"Profil {profile_name}"
                                scan_total = 1
                                scan_done = 0
                                scan_current_host = self.last_target
                                scan_estimated_sec = self._estimate_profile_duration(profile_id, max(1, len(hosts)))
                                scan_started_at = time.time()
                                scan_elapsed_sec = 0.0
                                refresh_live()

                                self._run_profile_scan_on_network(self.last_target, profile_id, on_tick=refresh_live)
                                scan_done = 1
                                refresh_live()

                                scan_running = False
                                scan_current_host = ""
                                scan_elapsed_sec = time.time() - scan_started_at
                                self.discovery_logs.append(f"Profil {profile_name} terminé.")
                        elif extra_menu_active:
                            if extra_menu_idx == 3:
                                extra_menu_active = False
                            else:
                                scan_map = {
                                    0: ("tcp_udp", "Scan TCP/UDP"),
                                    1: ("tcp", "Scan TCP"),
                                    2: ("udp", "Scan UDP"),
                                }
                                scan_mode, scan_label = scan_map[extra_menu_idx]
                                params = prompt_additional_params_safe(scan_label)
                                if params is not None:
                                    port_start, port_end, extra_ports = params
                                    targets = [self.last_target]
                                    self.discovery_logs.append(
                                        f"Lancement {scan_label} sur réseau {self.last_target} | plage {port_start}-{port_end} | extras={extra_ports or 'aucun'}"
                                    )
                                    scan_running = True
                                    scan_action_label = scan_label
                                    scan_total = 1
                                    scan_done = 0
                                    scan_current_host = self.last_target
                                    scan_estimated_sec = self._estimate_additional_duration(
                                        scan_mode,
                                        targets,
                                        port_start,
                                        port_end,
                                        extra_ports,
                                    )
                                    scan_started_at = time.time()
                                    scan_elapsed_sec = 0.0
                                    refresh_live()

                                    self._run_additional_scan_on_network(
                                        self.last_target,
                                        scan_mode,
                                        port_start,
                                        port_end,
                                        extra_ports,
                                        on_tick=refresh_live,
                                    )
                                    scan_done = 1
                                    refresh_live()

                                    scan_running = False
                                    scan_current_host = ""
                                    scan_elapsed_sec = time.time() - scan_started_at
                                    self.discovery_logs.append(f"Action {scan_label} terminée.")
                        else:
                            action_id, action_label = self.post_actions[action_idx]
                            if action_id == "extra":
                                extra_menu_active = True
                                extra_menu_idx = 0
                            elif action_id == "tags":
                                tags_menu_active = True
                                tags_menu_idx = 0
                            elif action_id == "vulns":
                                vuln_menu_active = True
                                vuln_menu_idx = 0
                            elif action_id == "profiles":
                                profile_menu_active = True
                                profile_menu_idx = 0
                            elif action_id == "export":
                                scan_running = True
                                scan_action_label = "Export JSON/HTML"
                                scan_total = 1
                                scan_done = 0
                                scan_current_host = self.last_target
                                scan_estimated_sec = 2.0
                                scan_started_at = time.time()
                                scan_elapsed_sec = 0.0
                                refresh_live()

                                json_path, html_path = self._export_session_reports(hosts)
                                scan_done = 1
                                scan_running = False
                                scan_current_host = ""
                                scan_elapsed_sec = time.time() - scan_started_at
                                self.discovery_logs.append(f"Export JSON: {json_path}")
                                self.discovery_logs.append(f"Export HTML: {html_path}")
                            else:
                                targets = [hosts[host_idx]] if not selected_hosts else [h for h in hosts if h in selected_hosts]
                                self.discovery_logs.append(f"Lancement {action_label} sur {len(targets)} hôte(s)")
                                scan_running = True
                                scan_action_label = action_label
                                scan_total = len(targets)
                                scan_done = 0
                                scan_current_host = ""
                                scan_estimated_sec = self._estimate_action_duration(action_id, targets)
                                scan_started_at = time.time()
                                scan_elapsed_sec = 0.0
                                refresh_live()

                                for target_host in targets:
                                    scan_current_host = target_host
                                    refresh_live()
                                    self._run_action_on_host(action_id, target_host, on_tick=refresh_live)
                                    scan_done += 1
                                    refresh_live()

                                scan_running = False
                                scan_current_host = ""
                                scan_elapsed_sec = time.time() - scan_started_at
                                self.discovery_logs.append(f"Action {action_label} terminée.")

                    max_scroll = max(0, len(self.discovery_logs) - 14)
                    log_scroll = min(log_scroll, max_scroll)

                    current_host = hosts[host_idx] if hosts else ""
                    if current_host:
                        detail_len = 6 + len(self._analysis_for_host(current_host).ensure_findings())
                        detail_scroll = min(detail_scroll, max(0, detail_len - 14))
                    else:
                        detail_scroll = 0

                    refresh_live()
                    time.sleep(0.05)
        finally:
            if use_raw and old_settings is not None:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def _reader_thread(self, process: subprocess.Popen[str], output_queue: queue.Queue[str], file_obj: Any) -> None:
        if process.stdout is None:
            return
        for line in process.stdout:
            file_obj.write(line)
            file_obj.flush()
            output_queue.put(line.rstrip("\n"))

    def _run_startup_discovery_live(self, network: ipaddress.IPv4Network) -> tuple[bool, str, list[str], set[str], int]:
        """Lance la découverte hôtes initiale avec rendu temps réel.

        Returns:
            (success, error_message, hosts, selected_hosts, selected_index)
        """
        cmd = [
            "nmap",
            "-sn",
            "-PR",
            "-PE",
            "-PP",
            "-PM",
            "-PS21,22,25,53,80,110,139,443,445,3389",
            "-PA21,22,80,443,3389",
            "-PU53,67,68,123,161",
            "-T4",
            str(network),
            "-oA",
            str(self.discovery_oa_base),
            "-oX",
            str(self.result_xml),
            "-oN",
            str(self.result_txt),
        ]
        logs: list[str] = [f"Commande: {' '.join(cmd)}"]
        hosts: list[str] = []
        selected_hosts: set[str] = set()
        selected_idx = 0

        try:
            with self.result_txt.open("w", encoding="utf-8", errors="replace") as out_file:
                process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
                output_queue: queue.Queue[str] = queue.Queue()
                reader = threading.Thread(target=self._reader_thread, args=(process, output_queue, out_file), daemon=True)
                reader.start()

                old_settings = None
                use_raw = platform.system().lower() != "windows" and sys.stdin.isatty()
                if use_raw:
                    fd = sys.stdin.fileno()
                    old_settings = termios.tcgetattr(fd)
                    tty.setcbreak(fd)

                try:
                    with Live(
                        self._render_discovery_layout(network, logs, hosts, selected_idx, running=True),
                        refresh_per_second=12,
                        console=self.ui.console,
                        screen=True,
                    ) as live:
                        while True:
                            drained = False
                            while True:
                                try:
                                    line = output_queue.get_nowait()
                                except queue.Empty:
                                    break
                                drained = True
                                logs.append(line)
                                if line.startswith("Nmap scan report for "):
                                    host = line.replace("Nmap scan report for ", "", 1).strip()
                                    if host and host not in hosts:
                                        hosts.append(host)
                                        self._analysis_for_host(host)
                                        if len(hosts) == 1:
                                            selected_idx = 0

                            key = self._read_key_nonblocking()
                            if key == "UP" and hosts:
                                selected_idx = max(0, selected_idx - 1)
                            elif key == "DOWN" and hosts:
                                selected_idx = min(len(hosts) - 1, selected_idx + 1)
                            elif key == "SPACE" and hosts:
                                selected_host = hosts[selected_idx]
                                if selected_host in selected_hosts:
                                    selected_hosts.remove(selected_host)
                                else:
                                    selected_hosts.add(selected_host)

                            running = process.poll() is None
                            live.update(self._render_discovery_layout(network, logs, hosts, selected_idx, running=running, selected_hosts=selected_hosts))

                            if not running and not drained and output_queue.empty():
                                break

                            time.sleep(0.05)

                        live.update(self._render_discovery_layout(network, logs, hosts, selected_idx, running=False, selected_hosts=selected_hosts))
                finally:
                    if use_raw and old_settings is not None:
                        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

                self.discovery_logs = logs[:]
                return process.returncode == 0, "", hosts[:], selected_hosts, selected_idx
        except Exception as exc:
            return False, str(exc), [], set(), 0

    def _parse_windows_interfaces(self, output: str, wifi_names: set[str] | None = None) -> list[NetworkInterface]:
        wifi_names = wifi_names or set()
        interfaces: list[NetworkInterface] = []
        blocks = re.split(r"\r?\n\r?\n+", output)
        for block in blocks:
            lines = [line.rstrip() for line in block.splitlines() if line.strip()]
            if not lines:
                continue

            header = lines[0].strip()
            if "adapter" not in header.lower() and "carte" not in header.lower():
                continue

            name = re.sub(r"^(Ethernet adapter|Wireless LAN adapter)\s+", "", header, flags=re.IGNORECASE)
            name = re.sub(r"^(Carte Ethernet|Carte réseau sans fil)\s+", "", name, flags=re.IGNORECASE)
            name = name.rstrip(":").strip()
            is_wifi = self._is_wifi_name(header) or self._is_wifi_name(name) or name in wifi_names
            ipv4 = ""
            netmask = ""

            for line in lines[1:]:
                lower = line.lower()
                if ("ipv4" in lower or "adresse ipv4" in lower) and ":" in line:
                    value = line.split(":", 1)[1].strip()
                    value = value.replace("(Preferred)", "").replace("(préféré)", "").strip()
                    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
                        ipv4 = value
                if ("subnet mask" in lower or "masque de sous-réseau" in lower) and ":" in line:
                    value = line.split(":", 1)[1].strip()
                    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", value):
                        netmask = value

            if ipv4 and netmask:
                interfaces.append(NetworkInterface(name=name, ipv4=ipv4, netmask=netmask, is_wifi=is_wifi, active_ipv4=True))
            elif is_wifi:
                interfaces.append(NetworkInterface(name=name, ipv4="N/A", netmask="N/A", is_wifi=True, active_ipv4=False))

        return interfaces

    def _parse_unix_interfaces(self, output: str) -> list[NetworkInterface]:
        interfaces: list[NetworkInterface] = []
        for line in output.splitlines():
            line = line.strip()
            if " inet " not in line:
                continue
            if line.startswith("127.") or " lo " in f" {line} ":
                continue

            match = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if not match:
                continue

            ip_addr = match.group(1)
            prefix = int(match.group(2))
            name_match = re.match(r"\d+:\s*([^:]+):", line)
            if name_match:
                iface_name = name_match.group(1)
            else:
                iface_name = "interface"

            net = ipaddress.IPv4Network(f"0.0.0.0/{prefix}")
            netmask = str(net.netmask)
            interfaces.append(NetworkInterface(name=iface_name, ipv4=ip_addr, netmask=netmask, is_wifi=self._is_wifi_name(iface_name)))

        return interfaces

    def list_network_interfaces(self) -> list[NetworkInterface]:
        """Retourne les interfaces IPv4 détectées selon l'OS courant."""
        system = platform.system().lower()
        try:
            if system == "windows":
                wifi_names = self._windows_wifi_names()
                result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    return self._parse_windows_interfaces(result.stdout, wifi_names=wifi_names)
                return []

            result = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show"], capture_output=True, text=True, check=False)
            if result.returncode == 0:
                return self._parse_unix_interfaces(result.stdout)

            fallback = subprocess.run(["ifconfig"], capture_output=True, text=True, check=False)
            if fallback.returncode == 0:
                return self._parse_unix_interfaces(fallback.stdout)
            return []
        except Exception:
            return []

    def choose_interface(self) -> NetworkInterface | None:
        """Affiche les interfaces et retourne celle choisie par l'utilisateur."""
        interfaces = self.list_network_interfaces()
        if not interfaces:
            self.ui.warn("Impossible de détecter des interfaces IPv4 actives.")
            return None

        self.ui.clear()
        self.ui.banner()
        self.ui.title("Choix de l'interface réseau")
        self.ui.table_interfaces(interfaces)

        default_index = 1
        for idx, iface in enumerate(interfaces, start=1):
            if iface.is_wifi and iface.active_ipv4:
                default_index = idx
                break
        if default_index == 1:
            for idx, iface in enumerate(interfaces, start=1):
                if iface.active_ipv4:
                    default_index = idx
                    break

        raw = self.ui.ask("Sélectionnez l'interface (numéro)", default=str(default_index))
        try:
            selected = int(raw)
        except ValueError:
            self.ui.warn(f"Choix invalide, interface {default_index} sélectionnée par défaut.")
            selected = default_index

        if selected < 1 or selected > len(interfaces):
            self.ui.warn(f"Choix hors plage, interface {default_index} sélectionnée par défaut.")
            selected = default_index

        selected_iface = interfaces[selected - 1]
        if not selected_iface.active_ipv4:
            self.ui.warn("Interface détectée mais sans IPv4 active (probablement non connectée). Impossible de scanner le réseau IP avec celle-ci.")
            self.ui.wait()
            active_interfaces = [item for item in interfaces if item.active_ipv4]
            if not active_interfaces:
                return None
            selected_iface = active_interfaces[0]
            self.ui.info(f"Bascule automatique vers: {selected_iface.name} ({selected_iface.ipv4})")
        self.selected_interface = selected_iface
        return selected_iface

    def choose_start_mode(self) -> str | None:
        """Demande le mode de démarrage (`interface` ou `manual`)."""
        self.ui.clear()
        self.ui.banner()
        self.ui.title("Mode de démarrage")
        self.ui.info("1. Mode par interface (sélection d'une interface locale)")
        self.ui.info("2. Mode manuel (saisie réseau CIDR ex: 192.168.1.0/24)")
        self.ui.info("3. Annuler")

        choice = self.ui.ask("Choisissez le mode", default="1").strip()
        if choice == "1":
            return "interface"
        if choice == "2":
            return "manual"
        return None

    def ask_manual_network(self) -> ipaddress.IPv4Network | None:
        default_value = self.last_target if "/" in self.last_target else "192.168.1.0/24"
        raw = self.ui.ask("Entrez le réseau CIDR", default=default_value).strip()
        if not raw:
            return None
        if "/" not in raw:
            self.ui.warn("Format attendu: réseau CIDR (ex: 192.168.1.0/24)")
            return None
        try:
            return ipaddress.IPv4Network(raw, strict=False)
        except Exception:
            self.ui.warn("Réseau CIDR invalide.")
            return None

    def count_discovered_hosts(self) -> int:
        if not self.result_txt.exists():
            return 0
        content = self.result_txt.read_text(encoding="utf-8", errors="replace")
        return len(re.findall(r"^Nmap scan report for ", content, flags=re.MULTILINE))

    def startup_host_discovery(self) -> None:
        """Workflow d'entrée: choix du réseau puis découverte des hôtes."""
        mode = self.choose_start_mode()
        if mode is None:
            self.ui.warn("Démarrage annulé.")
            return

        iface: NetworkInterface | None = None
        if mode == "interface":
            iface = self.choose_interface()
            if iface is None:
                return
            try:
                network = ipaddress.IPv4Network(f"{iface.ipv4}/{iface.netmask}", strict=False)
            except Exception:
                self.ui.warn("Impossible de calculer le réseau depuis l'interface choisie.")
                return
        else:
            self.selected_interface = None
            manual_network = self.ask_manual_network()
            if manual_network is None:
                self.ui.warn("Aucun réseau manuel valide fourni.")
                return
            network = manual_network

        self.last_target = str(network)
        self.session_mode = mode
        self.session_network = self.last_target
        if iface is not None:
            self.session_interface = f"{iface.name} ({iface.ipv4})"
            self.ui.info(f"Interface choisie: {iface.name} ({iface.ipv4})")
        else:
            self.session_interface = "manual"
            self.ui.info("Mode manuel sélectionné.")
        self.ui.info(f"Scan rapide des hôtes sur le réseau: {network}")

        if RICH_AVAILABLE:
            ok, error_message, hosts, selected_hosts, selected_idx = self._run_startup_discovery_live(network)
            if not ok and error_message:
                self.ui.error(f"Erreur pendant le scan des hôtes: {error_message}")
                self.ui.wait()
                return
            success = ok
        else:
            cmd = [
                "nmap",
                "-sn",
                "-PR",
                "-PE",
                "-PP",
                "-PM",
                "-PS21,22,25,53,80,110,139,443,445,3389",
                "-PA21,22,80,443,3389",
                "-PU53,67,68,123,161",
                "-T4",
                str(network),
                "-oA",
                str(self.discovery_oa_base),
                "-oX",
                str(self.result_xml),
                "-oN",
                str(self.result_txt),
            ]
            try:
                completed = subprocess.run(cmd, capture_output=True, text=True, check=False)
                success = completed.returncode == 0
                if not success and completed.stderr.strip():
                    self.ui.warn(completed.stderr.strip())
            except Exception as exc:
                self.ui.error(f"Erreur pendant le scan des hôtes: {exc}")
                self.ui.wait()
                return

        if success:
            self.ui.ok("Scan des hôtes terminé.")
            self.last_discovery_count = self.count_discovered_hosts()
            self.ui.info(f"Hôtes détectés: {self.last_discovery_count}")
            if RICH_AVAILABLE:
                self._post_scan_dashboard(hosts, selected_hosts, selected_idx)
            else:
                self.show_results(limit_lines=120)
        else:
            self.ui.error("Le scan des hôtes a échoué.")
            self.ui.wait()

    def check_deps(self) -> bool:
        """Valide la présence de Nmap dans le PATH."""
        if shutil.which("nmap") is None:
            self.ui.error("nmap est introuvable dans le PATH.")
            self.ui.info("Installez nmap puis relancez le script.")
            return False
        return True

    def show_results(self, limit_lines: int | None = None) -> None:
        if not self.result_txt.exists():
            self.ui.warn("Aucun résultat disponible.")
            self.ui.wait()
            return

        content = self.result_txt.read_text(encoding="utf-8", errors="replace")
        lines = content.splitlines()
        shown = lines if limit_lines is None else lines[:limit_lines]

        self.ui.clear()
        self.ui.title("Derniers résultats Nmap")
        if RICH_AVAILABLE:
            for line in shown:
                self.ui.console.print(line)
        else:
            print("\n".join(shown))

        if limit_lines is not None and len(lines) > limit_lines:
            self.ui.info(f"Affichage limité à {limit_lines} lignes sur {len(lines)}.")
            if self.ui.confirm("Afficher le rapport complet ?", default_yes=False):
                self.show_results(limit_lines=None)
                return
        self.ui.wait()

    def run(self) -> None:
        """Point d'entrée applicatif du mode terminal."""
        if not self.check_deps():
            return

        if not RICH_AVAILABLE:
            self.ui.warn("Module 'rich' non installé: confort visuel réduit.")
            self.ui.info("Optionnel: pip install rich")

        self.startup_host_discovery()
        self.ui.ok("Auto scan terminé.")


def main() -> None:
    AutoScanTUI().run()


if __name__ == "__main__":
    main()
