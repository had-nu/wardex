package ingestion

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/had-nu/wardex/pkg/model"
)

func loadCSV(path string) ([]model.ExistingControl, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing CSV: %w", err)
	}

	if len(records) < 2 {
		return nil, nil // Empty or just header
	}

	// Assuming header: id,name,description,framework,domains,maturity,evidences,context_weight,weight_justification
	// Evidences -> pipe separated: type1:ref1|type2:ref2
	// Domains -> pipe separated: domain1|domain2

	header := records[0]
	idx := make(map[string]int)
	for i, h := range header {
		idx[strings.TrimSpace(strings.ToLower(h))] = i
	}

	var controls []model.ExistingControl
	for i := 1; i < len(records); i++ {
		row := records[i]

		get := func(key string) string {
			if pos, ok := idx[key]; ok && pos < len(row) {
				return row[pos]
			}
			return ""
		}

		id := get("id")
		name := get("name")
		desc := get("description")
		framework := get("framework")

		domStr := get("domains")
		var domains []string
		if domStr != "" {
			domains = strings.Split(domStr, "|")
		}

		maturityStr := get("maturity")
		maturity, _ := strconv.Atoi(maturityStr)

		evidenceStr := get("evidences")
		var evidences []model.Evidence
		if evidenceStr != "" {
			parts := strings.Split(evidenceStr, "|")
			for _, p := range parts {
				kv := strings.SplitN(p, ":", 2)
				if len(kv) == 2 {
					evidences = append(evidences, model.Evidence{Type: kv[0], Ref: kv[1]})
				}
			}
		}

		cwStr := get("context_weight")
		cw := 1.0
		if cwStr != "" {
			cwParsed, err := strconv.ParseFloat(cwStr, 64)
			if err == nil {
				cw = cwParsed
			}
		}

		wj := get("weight_justification")

		mapped := model.ExistingControl{
			ID:                  id,
			Name:                name,
			Description:         desc,
			Framework:           framework,
			Domains:             domains,
			Maturity:            maturity,
			Evidences:           evidences,
			ContextWeight:       cw,
			WeightJustification: wj,
		}

		if err := validateControl(mapped, i); err != nil {
			return nil, err
		}
		controls = append(controls, mapped)
	}

	return controls, nil
}
