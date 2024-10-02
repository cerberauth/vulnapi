package seclist

import (
	"bufio"
	"embed"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
)

//go:embed lists/*.txt
var sectlistsFolder embed.FS

type SecList struct {
	Name  string
	Items []string
}

func fileNameFromURL(url string) string {
	return path.Base(url)
}

func hasSecList(name string) bool {
	_, err := sectlistsFolder.Open("lists/" + name)
	return err == nil
}

func NewSecList(name string) *SecList {
	return &SecList{
		Name:  name,
		Items: []string{},
	}
}

func NewSecListFromURL(name, url string) (*SecList, error) {
	filename := fileNameFromURL(url)
	if hasSecList(filename) {
		return NewSecListFromEmbeddedFile(name, filename)
	}

	s := NewSecList(name)
	err := s.DownloadFromURL(url)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SecList) loadFile(file fs.File) error {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		s.Items = append(s.Items, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return nil
}

func (s *SecList) loadFromEmbeddedFile(filepath string) error {
	file, err := sectlistsFolder.Open("lists/" + filepath)
	if err != nil {
		return err
	}

	return s.loadFile(file)
}

func NewSecListFromEmbeddedFile(name, filename string) (*SecList, error) {
	s := NewSecList(name)
	err := s.loadFromEmbeddedFile(filename)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SecList) loadFromTmpFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	return s.loadFile(file)
}

func (s *SecList) DownloadFromURL(url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New("sec list download failed")
	}

	tempFile, err := os.CreateTemp("", "seclist")
	if err != nil {
		return err
	}
	defer tempFile.Close()

	_, err = io.Copy(tempFile, resp.Body)
	if err != nil {
		return err
	}

	filepath := tempFile.Name()
	err = s.loadFromTmpFile(filepath)
	if err != nil {
		return err
	}

	err = os.Remove(filepath)
	if err != nil {
		return err
	}

	return nil
}
