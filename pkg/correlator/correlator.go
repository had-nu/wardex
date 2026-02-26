package correlator

import "github.com/had-nu/wardex/pkg/model"

type Correlator struct {
	Catalog []model.AnnexAControl
}

func New(catalog []model.AnnexAControl) *Correlator {
	return &Correlator{Catalog: catalog}
}

// Correlate maps an array of implemented controls against the catalog
func (c *Correlator) Correlate(controls []model.ExistingControl) []model.Mapping {
	var mappings []model.Mapping

	for _, ext := range controls {
		for _, anx := range c.Catalog {
			res := Match(ext, anx)
			if res.Matched {
				mappings = append(mappings, model.Mapping{
					ExistingControlID: ext.ID,
					AnnexAControlID:   anx.ID,
					Confidence:        res.Confidence,
					MatchedDomains:    res.MatchedDomains,
					MatchedKeywords:   res.MatchedKeywords,
				})
			}
		}
	}

	return mappings
}
