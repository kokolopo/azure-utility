package utility

import (
	"encoding/json"
	"fmt"
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

type GraphUser struct {
	ODataContext      string   `json:"@odata.context"`
	BusinessPhones    []string `json:"businessPhones"`
	DisplayName       string   `json:"displayName"`
	GivenName         string   `json:"givenName"`
	JobTitle          *string  `json:"jobTitle"` // Pointer untuk menangani null
	Mail              string   `json:"mail"`
	MobilePhone       *string  `json:"mobilePhone"`       // Pointer untuk menangani null
	OfficeLocation    *string  `json:"officeLocation"`    // Pointer untuk menangani null
	PreferredLanguage *string  `json:"preferredLanguage"` // Pointer untuk menangani null
	Surname           string   `json:"surname"`
	UserPrincipalName string   `json:"userPrincipalName"`
	ID                string   `json:"id"`
}

type AzureErrorResponse struct {
	AError AzureErrorDetail `json:"error"`
}

func (e *AzureErrorResponse) Error() string {
	return fmt.Sprintf("Azure Error [%s]: %s", e.AError.Code, e.AError.Message)
}

type AzureErrorDetail struct {
	Code       string     `json:"code"`
	Message    string     `json:"message"`
	InnerError InnerError `json:"innerError"`
}

type InnerError struct {
	Date            string `json:"date"`              // Menggunakan string untuk keamanan parsing format waktu
	RequestID       string `json:"request-id"`        // Perhatikan dash (-) pada json tag
	ClientRequestID string `json:"client-request-id"` // Perhatikan dash (-) pada json tag
}

func GetToken(url string, payload url.Values) (string, error) {

	encodedData := payload.Encode()

	// 3. Buat Request baru. Gunakan strings.NewReader karena encodedData adalah string
	req, err := http.NewRequest("POST", url, strings.NewReader(encodedData))
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

func GetUserByEmailOrID(url, token, emailOrID string) (GraphUser, AzureErrorResponse, error) {
	req, err := http.NewRequest("GET", url+"/"+emailOrID, nil)
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making GET request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		var azureErr AzureErrorResponse
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading response body: %v", err)
		}
		json.Unmarshal(body, &azureErr)
		return GraphUser{}, azureErr, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %v", err)
	}

	var graphUserResp GraphUser
	json.Unmarshal(body, &graphUserResp)

	return graphUserResp, AzureErrorResponse{}, nil
}
