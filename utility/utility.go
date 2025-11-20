package utility

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type Azul struct {
}

func (u *Azul) GetToken(url string, payload url.Values) (string, error) {

	encodedData := payload.Encode()

	// 3. Buat Request baru. Gunakan strings.NewReader karena encodedData adalah string
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/6175c024-2e27-41d2-b020-5d4419dc6a9a/oauth2/v2.0/token", strings.NewReader(encodedData))
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making POST request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	var tokenResp TokenResponse
	json.Unmarshal(body, &tokenResp)

	return tokenResp.AccessToken, nil
}
