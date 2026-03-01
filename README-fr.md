<div align="center">
  <h1>Wardex</h1>
  <p><b>Analyse des Écarts, Passerelle de Mise en Production Basée sur les Risques et Impact Commercial — Outil CLI & Moteur en Go</b></p>

  [![Wardex](https://img.shields.io/badge/Risk--based_Release-Wardex_v1-FF00FF?style=flat-square&logo=data:image/svg%2bxml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNiIgaGVpZ2h0PSIxNiI+PHRleHQgeD0iMiIgeT0iMTQiIGZpbGw9IndoaXRlIiBmb250LXNpemU9IjE2IiBmb250LWZhbWlseT0ic2VyaWYiPs6pPC90ZXh0Pjwvc3ZnPgo=)](https://github.com/had-nu/wardex)
  ![Go](https://img.shields.io/badge/Made_with-Go-00ADD8?style=flat-square&logo=go&logoColor=white)
  [![Go Report Card](https://goreportcard.com/badge/github.com/had-nu/wardex?style=flat-square)](https://goreportcard.com/report/github.com/had-nu/wardex)
  ![ISO-27001](https://img.shields.io/badge/Compliance-ISO_27001%3A2022-8A2BE2?style=flat-square&logo=checkmarx&logoColor=white)
  [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-8A2BE2.svg?style=flat-square&logo=gnu&logoColor=white)](https://www.gnu.org/licenses/agpl-3.0)
  [![Powered by lazy.go](https://img.shields.io/badge/Powered_by-lazy.go-8A2BE2?style=flat-square&logo=go&logoColor=white)](https://github.com/had-nu/lazy.go)

  <br>
  <a href="README-en.md">English</a> | <a href="README-fr.md">Français</a> | <a href="README-es.md">Castellano</a> | <a href="README.md">Português</a>
  <br><br>

  <img src="doc/banner.png" alt="Wardex Secure Release Gate Banner" width="800">
</div>

Wardex est un outil d'interface en ligne de commande (CLI) écrit en Go qui intègre les contrôles de sécurité déjà mis en œuvre dans votre organisation et les associe aux 93 contrôles de la norme ISO/CEI 27001:2022 (Annexe A).

Plus qu'un simple outil de conformité, Wardex agit comme une **Passerelle de Mise en Production Basée sur les Risques (Risk-Based Release Gate)** dans vos pipelines CI/CD. Au lieu de bloquer les sorties de logiciels sur la base de métriques binaires et statiques (comme "CVSS > 7.0"), Wardex calcule le risque réel de mise en production en ajustant la vulnérabilité technique à l'impact commercial, à l'exposition de l'infrastructure et aux contrôles compensatoires existants.

## Pourquoi Wardex ?

Consultez la documentation dans `/doc` pour comprendre la vision architecturale et les problèmes commerciaux résolus par l'outil :
- [Vision Commerciale (BUSINESS_VIEW.md)](doc/BUSINESS_VIEW.md)
- [Architecture Technique et Mathématiques (TECHNICAL_VIEW.md)](doc/TECHNICAL_VIEW.md)

## Compilation et Installation

Assurez-vous d'avoir installé [Go (>= 1.21)](https://go.dev/doc/install).

### Option 1 : Installation Globale (Recommandé)
Vous pouvez installer Wardex directement sur votre système, ce qui vous permet d'exécuter la commande `wardex` n'importe où :

```bash
go install github.com/had-nu/wardex@latest
```
*(Assurez-vous que le répertoire `$(go env GOPATH)/bin` est inclus dans votre `$PATH` ou environnement)*

### Option 2 : Compilation Locale à partir du Code Source
Si vous préférez cloner le dépôt pour tester ou développer localement :

```bash
git clone https://github.com/had-nu/wardex.git
cd wardex
go build -o wardex .
```

### Mise à jour vers la Dernière Version
Lorsqu'un nouveau correctif ou une version mineure est publié (par exemple, `v1.1.1`), vous pouvez mettre à jour en récupérant le code ou la balise la plus récente et en recompilant :

```bash
# Pour les installations globales
go install github.com/had-nu/wardex@latest

# Pour les builds locaux (ex: cibler une balise spécifique)
git fetch --tags
git checkout v1.1.1
go build -o wardex .
```

Veuillez consulter le [CHANGELOG.md](CHANGELOG.md) pour obtenir des détails sur les notes de publication et les correctifs.

## Utilisation

Wardex vous permet d'intégrer des politiques dans un format YAML ou JSON simple, de recouper des vulnérabilités (par ex., sortie de Grype) dans un fichier cible et de valider la passerelle :

```bash
./bin/wardex --config=test/testdata/wardex-config.yaml --gate=test/testdata/vulnerabilities.yaml test/testdata/dummy_controls.yaml
```

Cela génère des rapports visuels (en Markdown, CSV ou JSON) exposant l'Analyse de Maturité des 4 domaines mondiaux de la norme ISO 27001 (Personnes, Processus, Technologique et Physique) et exécute des politiques de décision (ALLOW / BLOCK) en fonction du risque étalonné de l'organisation.

## Nouveautés (v1.2.0)

- **Simulateur de Risque Interactif (`wardex simulate`)**: Utilisez la commande `simulate` pour générer et ouvrir un tableau de bord web interactif hors ligne qui permet de tester en temps réel comment le CVSS, l'EPSS et les contrôles de compensation affectent le score de risque de votre organisation.
- **Convertisseur Grype (`wardex convert grype`)**: Convertissez facilement la sortie JSON du scanner de vulnérabilités Grype au format YAML natif de Wardex, idéal pour une intégration immédiate dans les pipelines CI/CD.
- **Bande de Risque Modéré (`warn_above`)**: Permet d'approuver les versions tout en émettant des avertissements détaillées lorsque le risque dépasse un seuil inférieur sûr mais n'a pas encore enfreint l'appétit pour le risque fatal de l'organisation.

## Utilisation en tant que Bibliothèque (SDK)

L'architecture de **Wardex** a été conçue avec une forte séparation des responsabilités (dans le répertoire `pkg/`). Cela signifie qu'en plus d'utiliser la CLI, Wardex peut être importé comme bibliothèque (SDK) dans n'importe quel autre projet Go, tel qu'une API REST, un service d'orchestration GRC ou un bot.

Exemple de soumission programmatique pour une évaluation par *Risk-Based Release Gate* :

```go
package main

import (
	"fmt"

	"github.com/had-nu/wardex/pkg/model"
	"github.com/had-nu/wardex/pkg/releasegate"
)

func main() {
	// Configurez le contexte de l'organisation et de l'actif
	gate := releasegate.Gate{
		AssetContext: model.AssetContext{
			Criticality:    0.9,
			InternetFacing: true,
			RequiresAuth:   true,
		},
		CompensatingControls: []model.CompensatingControl{
			{Type: "waf", Effectiveness: 0.35},
		},
		RiskAppetite: 6.0,
	}

	vulns := []model.Vulnerability{
		{CVEID: "CVE-2024-1234", CVSSBase: 9.1, EPSSScore: 0.84, Reachable: true},
	}

	// Évaluez le risque composé directement dans votre code
	report := gate.Evaluate(vulns)

	fmt.Printf("La décision du Gate pour ce lancement a été : %s\n", report.OverallDecision)
}
```

## Gestion des Exceptions et Acceptation des Risques

Lorsque Wardex bloque un lancement pour dépassement de l'appétit de risque admissible, les organisations peuvent gérer les exceptions de manière formelle et auditable via le sous-commande `wardex accept` :

```bash
# Demander l'acceptation des risques pour une vulnérabilité bloquée
wardex accept request --report report.json --cve CVE-2024-1234 --accepted-by sec-lead@company.com --justification "Risque atténué par des contrôles externes" --expires 30d

# Vérifier l'intégrité cryptographique de toutes les acceptations actives
wardex accept verify
```

Wardex garantit l'intégrité de ces exceptions en utilisant des signatures HMAC-SHA256, des journaux d'audit à ajout seul (`JSONL`) et une détection de dérive de configuration (drift).

---
<div align="center">
  <a href="https://github.com/had-nu/lazy.go"><img src="https://img.shields.io/badge/Powered_by-lazy.go-8A2BE2?style=flat-square" alt="Powered by lazy.go"></a>
</div>
