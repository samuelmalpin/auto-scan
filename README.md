# Auto Scan Terminal

Scanner réseau semi-GUI en terminal basé sur Nmap, avec dashboard interactif.

## Objectif

Le script automatise un flux simple:

1. Choix du mode de départ (interface locale ou CIDR manuel)
2. Découverte rapide des hôtes du réseau
3. Analyse interactive post-scan (ports, fingerprint, vuln, profils, tags, export)

## Prérequis

- Python 3.10+
- Nmap installé et disponible dans le PATH
- Dépendance Python: `rich` (fallback texte possible si absent)

## Installation

Depuis la racine du projet:

```powershell
pip install -r scan/requirements.txt
```

Installer Nmap:

```powershell
winget install Insecure.Nmap
```

Linux Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y nmap python3-rich
```

## Lancement

```powershell
python scan/auto-scan.py
```

## Commandes clavier (dashboard)

- `TAB` : changer le focus entre options et hôtes
- `↑/↓` : naviguer
- `SPACE` : cocher/décocher un hôte
- `ENTER` : exécuter l'action sélectionnée
- `U` / `N` : scroll du journal
- `K` / `J` : scroll des détails hôte
- `Q` : quitter le dashboard

## Actions disponibles

- Découverte Ports
- Fingerprinting OS/Services
- Vulnérabilités (`light`, `advanced`, `full`)
- Catégorisation automatique (score 0-100)
- Tags d'actifs (Serveur, Poste, IoT, Critique, DMZ, Exposé Internet)
- Profils de scan réseau
- Scan supplémentaires (TCP/UDP + plage de ports)
- Export rapport JSON/HTML

## Sorties générées

- Fichiers temporaires Nmap:
	- XML: dossier temporaire système (`scan_result.xml`)
	- Texte: dossier temporaire système (`scan_result.txt`)
	- Découverte `-oA`: base `host_max_discovery` dans le dossier temporaire
- Exports de session:
	- Dossier `~/nmap_scans`
	- `session_report_YYYYMMDD_HHMMSS.json`
	- `session_report_YYYYMMDD_HHMMSS.html`

## Dépannage rapide

- `nmap` introuvable: relancer le terminal, vérifier `nmap --version`, puis réinstaller Nmap avec ajout au PATH.
- `rich` absent: exécuter `pip install -r scan/requirements.txt`.
- Navigation clavier étrange (Windows): tester dans Windows Terminal ou PowerShell standard.

## Avertissement

Utiliser uniquement sur des réseaux et hôtes autorisés. Certains scans peuvent être détectés ou considérés intrusifs.
