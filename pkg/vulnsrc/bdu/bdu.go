// Package bdu — источник данных Банка данных угроз безопасности информации (БДУ)
// ФСТЭК России для trivy-db.
//
// На фазе A источник работает как обогащение: для каждой CVE, на которую ссылается
// запись БДУ, он пишет VulnerabilityDetail под источником "fstec-bdu" (идентификатор
// БДУ, уровень опасности и CVSS 2.0 ФСТЭК, ссылка на бюллетень). Матчинг пакетов по
// данным БДУ — задел под фазу B.
//
// Вход — JSONL, подготовленный командой cmd/bdu-import из официальной выгрузки
// vulxml, по пути <dir>/fstec-bdu/bdu.jsonl.
package bdu

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/samber/oops"
	bolt "go.etcd.io/bbolt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/log"
	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

const (
	// каталог и файл с выгрузкой БДУ внутри рабочего каталога trivy-db.
	bduDir  = "fstec-bdu"
	bduFile = "bdu.jsonl"

	// bduVulURL — базовая ссылка на карточку уязвимости в БДУ ФСТЭК.
	bduVulURL = "https://bdu.fstec.ru/vul/"

	// maxLineBytes — верхняя граница длины строки JSONL (записи с большими
	// списками уязвимого ПО могут быть объёмными).
	maxLineBytes = 8 * 1024 * 1024
)

type VulnSrc struct {
	dbc    db.Operation
	logger *log.Logger
}

func NewVulnSrc() VulnSrc {
	return VulnSrc{
		dbc:    db.Config{},
		logger: log.WithPrefix("fstec-bdu"),
	}
}

func (vs VulnSrc) Name() types.SourceID {
	return vulnerability.FSTECBDU
}

func (vs VulnSrc) Update(dir string) error {
	filePath := filepath.Join(dir, bduDir, bduFile)
	eb := oops.In("fstec-bdu").With("file_path", filePath)

	entries, err := parseFile(filePath)
	if err != nil {
		return eb.Wrap(err)
	}

	if err := vs.save(entries); err != nil {
		return eb.Wrapf(err, "save error")
	}
	return nil
}

func parseFile(filePath string) ([]Entry, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, oops.Wrapf(err, "open error")
	}
	defer f.Close()

	var entries []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, oops.Wrapf(err, "json unmarshal error")
		}
		entries = append(entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, oops.Wrapf(err, "scan error")
	}
	return entries, nil
}

func (vs VulnSrc) save(entries []Entry) error {
	vs.logger.Info("Saving БДУ ФСТЭК", log.Int("entries", len(entries)))
	err := vs.dbc.BatchUpdate(func(tx *bolt.Tx) error {
		for _, e := range entries {
			if err := vs.put(tx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return oops.Wrapf(err, "batch update error")
	}
	return nil
}

func (vs VulnSrc) put(tx *bolt.Tx, e Entry) error {
	// Обогащение идёт через CVE. Записи без CVE (~4%) — задел под фазу B.
	if len(e.CVEs) == 0 {
		return nil
	}

	// SeverityLevel уже нормализован импортёром к градации Trivy; UNKNOWN и
	// нераспознанные значения дают SeverityUnknown.
	severity, _ := types.NewSeverity(e.SeverityLevel)

	references := make([]string, 0, len(e.Sources)+1)
	references = append(references, bduVulURL+e.ID)
	references = append(references, e.Sources...)

	detail := types.VulnerabilityDetail{
		ID:               e.ID, // идентификатор БДУ для данной CVE, напр. BDU:2024-00001
		CvssScore:        e.CVSS2Score,
		CvssVector:       e.CVSS2Vector,
		Severity:         severity,
		References:       references,
		Title:            e.Name,
		Description:      e.Description,
		PublishedDate:    parseDate(e.PublishDate),
		LastModifiedDate: parseDate(e.LastUpdate),
	}

	for _, cve := range e.CVEs {
		if err := vs.dbc.PutVulnerabilityDetail(tx, cve, vulnerability.FSTECBDU, detail); err != nil {
			return oops.With("cve", cve).With("bdu_id", e.ID).Wrapf(err, "put vulnerability detail")
		}
	}
	return nil
}

func parseDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
}
