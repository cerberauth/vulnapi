package report

import (
	"os"

	"gopkg.in/yaml.v2"
)

func loadYAMLFile(path string, v interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(data, v)
	if err != nil {
		return err
	}

	return nil
}
