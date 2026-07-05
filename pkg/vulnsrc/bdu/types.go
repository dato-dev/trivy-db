package bdu

// Entry — запись БДУ ФСТЭК из выгрузки cmd/bdu-import (JSONL).
// Поля соответствуют JSON-контракту пакета
// github.com/dato-dev/trivy-fork-bdu-fstek/pkg/bdu.Entry.
//
// Структура намеренно дублируется здесь, чтобы источник trivy-db оставался
// самодостаточным (как nvd.Cve и другие входные типы источников).
type Entry struct {
	ID            string   `json:"id"` // BDU:2024-00001
	Name          string   `json:"name,omitempty"`
	Description   string   `json:"description,omitempty"`
	CVEs          []string `json:"cves,omitempty"`
	CWEs          []string `json:"cwes,omitempty"`
	CVSS2Vector   string   `json:"cvss2_vector,omitempty"`
	CVSS2Score    float64  `json:"cvss2_score,omitempty"`
	SeverityLevel string   `json:"severity_level,omitempty"` // CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN
	Sources       []string `json:"sources,omitempty"`
	PublishDate   string   `json:"publish_date,omitempty"` // YYYY-MM-DD
	LastUpdate    string   `json:"last_update,omitempty"`  // YYYY-MM-DD
}
