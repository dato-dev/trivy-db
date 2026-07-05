package bdu

import (
	"path/filepath"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/utils"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrctest"
)

func TestVulnSrc_Update(t *testing.T) {
	tests := []struct {
		name       string
		dir        string
		wantValues []vulnsrctest.WantValues
		wantErr    string
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			wantValues: []vulnsrctest.WantValues{
				{
					Key: []string{"vulnerability-detail", "CVE-2022-27488", "fstec-bdu"},
					Value: types.VulnerabilityDetail{
						ID:               "BDU:2024-00001",
						Title:            "Тестовая уязвимость",
						Description:      "Описание",
						CvssScore:        9.7,
						CvssVector:       "AV:N/AC:L/Au:N/C:C/I:P/A:C",
						Severity:         types.SeverityHigh,
						References:       []string{"https://bdu.fstec.ru/vul/BDU:2024-00001", "https://fortiguard.com/psirt/FG-IR-22-038"},
						PublishedDate:    utils.MustTimeParse("2024-01-02T00:00:00Z"),
						LastModifiedDate: utils.MustTimeParse("2024-01-02T00:00:00Z"),
					},
				},
				{
					Key: []string{"vulnerability-detail", "CVE-2011-4859", "fstec-bdu"},
					Value: types.VulnerabilityDetail{
						ID:               "BDU:2014-00001",
						Title:            "Уязвимость Modicon",
						CvssScore:        10,
						CvssVector:       "AV:N/AC:L/Au:N/C:C/I:C/A:C",
						Severity:         types.SeverityCritical,
						References:       []string{"https://bdu.fstec.ru/vul/BDU:2014-00001"},
						PublishedDate:    utils.MustTimeParse("2016-07-07T00:00:00Z"),
						LastModifiedDate: utils.MustTimeParse("2016-11-28T00:00:00Z"),
					},
				},
			},
			// Запись BDU:2020-99999 без CVE не должна попасть в БД.
		},
		{
			name:    "sad path (dir doesn't exist)",
			dir:     filepath.Join("testdata", "badPath"),
			wantErr: "open error",
		},
		{
			name:    "sad path (failed to decode)",
			dir:     filepath.Join("testdata", "sad"),
			wantErr: "json unmarshal error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVulnSrc()
			vulnsrctest.TestUpdate(t, vs, vulnsrctest.TestUpdateArgs{
				Dir:        tt.dir,
				WantValues: tt.wantValues,
				WantErr:    tt.wantErr,
			})
		})
	}
}
