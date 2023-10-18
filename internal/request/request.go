package request

import (
	"fmt"
	"net/http"
)

func prepareVulnAPIRequest(method string, url string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "vulnapi/0.1")

	return req, nil
}

func SendRequestWithBearerAuth(url string, token string) (*http.Request, *http.Response, error) {
	req, err := prepareVulnAPIRequest("GET", url)
	if err != nil {
		return req, nil, err
	}

	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return req, resp, err
	}
	defer resp.Body.Close()

	return req, resp, nil
}
