package model

// ExistingControl representa um controle já implementado na organização.
type ExistingControl struct {
	ID                  string
	Name                string
	Description         string   // Usado no matching inferido
	Framework           string   // Informative
	Domains             []string // Temas semânticos declarados
	Maturity            int      // 1 (inicial) a 5 (otimizado)
	Evidences           []Evidence
	ContextWeight       float64 // Multiplicador de risco (default: 1.0)
	WeightJustification string  // Justificativa auditável
}

// CatalogControl representa um controle da ISO 27001:2022 Annex A.
type CatalogControl struct {
	ID            string     `yaml:"id"`
	Name          string     `yaml:"name"`
	Domain        string     `yaml:"domain"` // "organizational" | "people" | "physical" | "technological"
	Domains       []string   `yaml:"domains"`
	Keywords      []string   `yaml:"keywords"`
	EvidenceTypes []string   `yaml:"evidence_types"`
	BaseScore     float64    `yaml:"base_score"` // Criticidade base 0.0–10.0
	Practices     []Practice `yaml:"practices"`  // Práticas concretas que cobrem o controle
}

// Practice representa uma prática concreta associada a um controle Annex A.
// Para A.8.8: SCA scanner, release gate policy, SBOM generation.
type Practice struct {
	ID           string `yaml:"id"`
	Name         string `yaml:"name"`
	MinMaturity  int    `yaml:"min_maturity"`  // Maturidade mínima para cobertura válida
	GateRelevant bool   `yaml:"gate_relevant"` // true se esta prática corresponde a um release gate
}

// Evidence representa uma evidência declarada.
type Evidence struct {
	Type string // "policy" | "procedure" | "test_result" | "log" | "certificate" | "document"
	Ref  string
}

// Mapping representa a correlação entre um controle existente e um controle da Annex A.
type Mapping struct {
	ExistingControlID string
	CatalogControlID   string
	Confidence        string // "high" | "low"
	MatchedDomains    []string
	MatchedKeywords   []string
}
