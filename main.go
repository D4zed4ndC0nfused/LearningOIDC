package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"openidClient/jwt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type HttpBodyResponse struct {
	AccessToken           string `json:"access_token"`
	TokenType             string `json:"token_type"`
	ExpiresIn             int    `json:"expires_in"`
	Resource              string `json:"resource"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int    `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
	IdToken               string `json:"id_token"`
}

// Used for veryfying the signature
type PublicKey struct {
	Keys []Key `json:"keys"`
}

// Used for veryfying the signature
type Key struct {
	Kty string   `json:"kty"`
	Use string   `json:"use"`
	Kid string   `json:"kid"`
	X5T string   `json:"x5t"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type Config struct {
	ResponseType        string `json:"response_type"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	IDPAuthority        string `json:"idp_authority"`
	Grant_type          string `json:"grant_type"`
	Idp_Public_Key_Url  string `json:"idp_public_key_url"`
	Idp_Token_Url       string `json:"idp_token_url"`
}

type Tokens struct {
	AccessToken jwt.TokenPart
	IdToken     jwt.TokenPart
}

type TemplateData struct {
	Tokens                    Tokens
	RedirectURI               string
	ResponseBodyTokenEndpoint string `json:"response_body_token_endpoint"`
}

var RedirectURI string

func main() {

	portPtr := flag.Int("port", 8080, "port for the webserver")
	configPtr := flag.String("config", "", "path to config in json format (default \"./config.json\")")
	hostnamePtr := flag.String("hostname", "localhost", "hostname for the server")
	flag.Parse()

	var config Config

	if *configPtr != "" {
		config = readConfig(*configPtr)
	} else {
		fmt.Println("No config file provided, using default values ./config.json")
		config = readConfig("./config.json")
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "html/index.html")
	})

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		verifier, _ := generateCodeVerifier()
		challenge := generateCodeChallenge(verifier)

		http.SetCookie(w, &http.Cookie{
			Name:     "code_verifier",
			Value:    verifier,
			HttpOnly: true,
			Secure:   false,
		})

		params := url.Values{}
		params.Add("response_type", config.ResponseType)
		params.Add("client_id", config.ClientID)
		params.Add("redirect_uri", config.RedirectURI)
		params.Add("scope", config.Scope)
		params.Add("code_challenge", challenge)
		params.Add("code_challenge_method", config.CodeChallengeMethod)

		log.Printf("Redirecting to: %s\n", config.IDPAuthority+params.Encode())

		RedirectURI = config.IDPAuthority + params.Encode()

		http.Redirect(w, r, config.IDPAuthority+params.Encode(), http.StatusFound)

		log.Printf("Method: %s\n", r.Method)

	})

	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Callback")
		code := r.URL.Query().Get("code")
		cookie, err := r.Cookie("code_verifier")
		if err != nil {

			log.Println("Failed to get cookie: ", err)
			http.Error(w, "Failed to get cookie: "+err.Error(), http.StatusInternalServerError)
			return
		}

		params := url.Values{}
		params.Add("grant_type", config.Grant_type)
		params.Add("client_id", config.ClientID)
		params.Add("redirect_uri", config.RedirectURI)
		params.Add("code_verifier", cookie.Value)
		params.Add("code", code)

		//Check if this is secure
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}

		resp, err := client.PostForm(config.Idp_Token_Url, params)
		if err != nil {
			log.Println("Failed to exchange token: ", err)
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		defer resp.Body.Close()

		log.Println("Made POST request to token endpoint")

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("failed to read response body: %v", err)
			return
		}

		var HttpBodyResponse HttpBodyResponse
		err = json.Unmarshal(body, &HttpBodyResponse)
		if err != nil {
			log.Printf("failed to unmarshal response body: %v", err)
		}
		formattedBody, err := json.MarshalIndent(HttpBodyResponse, "", "  ")
		if err != nil {
			log.Printf("Failed to format JSON: %v", err)
			return
		}

		log.Printf("Response from /token endpoint: \n%s", string(formattedBody))

		publicKeyReq := getPublicKey(config.Idp_Public_Key_Url)
		log.Println("Getting IDP PublicKey from : ", config.Idp_Public_Key_Url)

		publicKeyBody, err := io.ReadAll(publicKeyReq.Body)
		if err != nil {
			log.Printf("failed to read response body: %v", err)
			return
		}

		log.Println("Public Key Body: ", string(publicKeyBody))

		var publikKey PublicKey
		err = json.Unmarshal(publicKeyBody, &publikKey)
		if err != nil {
			log.Printf("failed to unmarshal response body: %v", err)
		}

		log.Println("Public Key: ", publikKey.Keys[0].X5c[0])

		//AccessTokenParts Region

		accessTokenParts := strings.Split(HttpBodyResponse.AccessToken, ".")
		if len(accessTokenParts) != 3 {
			log.Printf("Access token is not a JWT")
		}

		accessTokenHeaderAttributes, err := decodeAndUnmarshal(accessTokenParts[0])
		if err != nil {
			log.Printf("Failed to decode and unmarshal header: %v", err)
		}

		accessTokenPayloadAttributes, err := decodeAndUnmarshal(accessTokenParts[1])
		if err != nil {
			log.Printf("Failed to decode and unmarshal payload: %v", err)
		}

		log.Print("Access Token Signature: ", accessTokenParts[2])

		accessTokenVerified := verifySignature(accessTokenParts[0], accessTokenParts[1], publikKey.Keys[0].X5c[0], accessTokenParts[2])
		log.Println("Access Token Signature Verified: ", accessTokenVerified)

		accessTokenSignatureAttributes := map[string]interface{}{"Signature": accessTokenVerified}

		accessToken := jwt.CreateTokenPart(accessTokenHeaderAttributes, accessTokenPayloadAttributes, accessTokenSignatureAttributes)

		//End AccessTokenParts Region

		//Start IdToken Region

		idTokenParts := strings.Split(HttpBodyResponse.IdToken, ".")
		if len(idTokenParts) != 3 {
			log.Print("Id token is not a JWT")
		}

		idTokenHeaderAttributes, err := decodeAndUnmarshal(idTokenParts[0])
		if err != nil {
			log.Printf("Failed to decode and unmarshal header: %v", err)
		}

		idTokenPayloadAttributes, err := decodeAndUnmarshal(idTokenParts[1])
		if err != nil {
			log.Printf("Failed to decode and unmarshal payload: %v", err)
		}

		log.Print("Id Token Signature: ", accessTokenParts[2])

		idTokenVerified := verifySignature(idTokenParts[0], idTokenParts[1], publikKey.Keys[0].X5c[0], idTokenParts[2])

		idTokenSignatureAttributes := map[string]interface{}{"Signature": idTokenVerified}
		log.Println("Id Token Signature Verified: ", accessTokenVerified)

		idToken := jwt.CreateTokenPart(idTokenHeaderAttributes, idTokenPayloadAttributes, idTokenSignatureAttributes)

		//End IdToken Region

		data := TemplateData{
			Tokens:                    Tokens{AccessToken: accessToken, IdToken: idToken},
			RedirectURI:               RedirectURI,
			ResponseBodyTokenEndpoint: string(formattedBody),
		}

		tmpl, err := template.ParseFiles("html/response_template.html")
		if err != nil {
			log.Printf("failed to parse template: %v", err)
		}

		err = tmpl.Execute(w, data)

		if err != nil {
			log.Printf("failed to execute template: %v", err)
			return
		}

	})

	browserURL := fmt.Sprintf("http://%v:%d", *hostnamePtr, *portPtr)

	go func() {
		err := exec.Command("brave", "--incognito", browserURL).Run()
		if err != nil {
			log.Println("Failed to open browser: ", err)
		}

	}()
	server := fmt.Sprintf("%v:%d", *hostnamePtr, *portPtr)
	log.Printf("Lyssnar på port: %d\n", *portPtr)
	log.Fatal(http.ListenAndServe(server, nil))

}

func generateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateCodeChallenge(verifier string) string {
	s := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(s[:])
}

func decodeAndUnmarshal(part string) (map[string]interface{}, error) {

	// Pad the part if necessary
	if len(part)%4 != 0 {
		part += strings.Repeat("=", 4-len(part)%4)
	}

	decodedPart, err := base64.URLEncoding.DecodeString(part)
	if err != nil {
		log.Printf("failed to decode part: %v", err)
		return nil, fmt.Errorf("failed to decode part: %v", err)
	}

	var attributes map[string]interface{}
	err = json.Unmarshal(decodedPart, &attributes)
	if err != nil {
		log.Printf("failed to decode part: %v", err)
		return nil, fmt.Errorf("failed to unmarshal part: %v", err)
	}

	for key, value := range attributes {
		switch key {
		case "iat", "nbf", "exp":
			timestamp := value.(float64)
			date := time.Unix(int64(timestamp), 0)
			attributes[key] = date
		}
	}

	return attributes, nil

}

func getPublicKey(url string) *http.Response {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		log.Println("Failed to exchange token: ", err)
	}

	return resp
}

func verifySignature(base64Header string, base64Payload string, publikKey string, signature string) bool {

	const lineLength = 64

	var b strings.Builder
	for i, rune := range publikKey {
		b.WriteRune(rune)
		if i > 0 && (i+1)%lineLength == 0 {
			b.WriteRune('\n')
		}
	}
	publikKeyWithBreaks := b.String()
	log.Println("Public Key with Breaks: ", publikKeyWithBreaks)
	formatedPublikKey := "-----BEGIN CERTIFICATE-----\n" + publikKeyWithBreaks + "\n-----END CERTIFICATE-----"
	log.Println("Formated Public Key: ", formatedPublikKey)

	pem, _ := pem.Decode([]byte(formatedPublikKey))
	if pem == nil {
		log.Println("Failed to decode public key")
		return false
	}

	//Parse the public key
	pubInterface, err := x509.ParseCertificate(pem.Bytes)
	if err != nil {
		log.Println("Failed to parse public key", err)
		return false
	}

	pub := pubInterface.PublicKey.(*rsa.PublicKey)
	if len(signature)%4 != 0 {
		signature += strings.Repeat("=", 4-len(signature)%4)
	}

	sig, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		log.Println("Failed to parse public key", err)
		return false
	}

	verificationString := base64Header + "." + base64Payload
	hashed := sha256.Sum256([]byte(verificationString))

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
	if err != nil {
		log.Println("Failed to verify signature", err)
		return false
	}

	return true
}

func readConfig(filename string) Config {
	file, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	var config Config
	err = json.Unmarshal(file, &config)
	if err != nil {
		log.Fatal(err)
	}

	return config
}
