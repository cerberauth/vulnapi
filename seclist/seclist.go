package seclist

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"os"
)

type SecList struct {
	Name  string
	Items []string
}

func NewSecList(name string) *SecList {
	return &SecList{
		Name:  name,
		Items: []string{},
	}
}

func NewSecListFromFile(name, filepath string) (*SecList, error) {
	s := NewSecList(name)
	err := s.ImportFromFile(filepath)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func NewSecListFromURL(name, url string) (*SecList, error) {
	s := NewSecList(name)
	err := s.DownloadFromURL(url)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SecList) ImportFromFile(filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

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
	err = s.ImportFromFile(filepath)
	if err != nil {
		return err
	}

	err = os.Remove(filepath)
	if err != nil {
		return err
	}

	return nil
}
