package utility

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
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

func ValidateAzureJWT(tokenString, tenantID, expectedAudience, expectedIssuer string) (jwt.MapClaims, error) {
	// JWKS URL dari Azure
	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)

	// Load JWKS
	jwks, err := keyfunc.Get(jwksURL, keyfunc.Options{
		RefreshInterval: time.Hour,
		RefreshErrorHandler: func(err error) {
			fmt.Printf("JWKS refresh error: %v\n", err)
		},
	})
	if err != nil {
		return nil, fmt.Errorf("gagal memuat JWKS: %w", err)
	}

	// Parse token
	token, err := jwt.Parse(tokenString, jwks.Keyfunc)
	if err != nil {
		return nil, fmt.Errorf("token tidak valid: %w", err)
	}

	// Validasi claim dasar
	if !token.Valid {
		return nil, fmt.Errorf("JWT tidak valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("gagal membaca claims")
	}

	// Validasi issuer dan audience
	if claims["iss"] != expectedIssuer {
		return nil, fmt.Errorf("issuer tidak cocok")
	}

	if claims["aud"] != expectedAudience {
		return nil, fmt.Errorf("audience tidak cocok")
	}

	return claims, nil
}

func SendEmail(token, sender, recipient, subject, content string) (int, error) {
	url := "https://graph.microsoft.com/v1.0/users/" + sender + "/sendMail"

	email := map[string]any{
		"message": map[string]any{
			"subject": subject,
			"body": map[string]any{
				"contentType": "HTML",
				"content":     content,
			},
			"toRecipients": []map[string]any{
				{
					"emailAddress": map[string]any{
						"address": recipient,
					},
				},
			},
		},
		"saveToSentItems": "true",
	}

	jsonData, err := json.Marshal(email)
	if err != nil {
		log.Fatalf("Error marshaling email data: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatalf("Error creating request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

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
	if resp.StatusCode != http.StatusAccepted {
		log.Fatalf("Error sending email: %s", body)
	}
	log.Println("Email sent successfully")
	return resp.StatusCode, nil
}
