package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/k-washi/jwt-decode/jwtdecode"
)

type envList struct {
	//export APP_PORT=8080
	//export KEY_URL=http://localhost/auth/realms/demo/protocol/openid-connect/token
	//export CLIENT_ID=demo_application
	//export CLIENT_SECRET=97e9be08-58a1-4482-aba3-4f803c3c11ea
	//export SVC_URL=http://localhost:8080/authorization
	Port          string
	KeyCloakUrl   string
	Client_id     string
	Client_secret string
	Serivce_url   string
}

type response struct {
	Result  string `json:"result"`
	Message string `json:"message"`
	ApiName string `json:"api"`
}

type token struct {
	Access_token       string `json:"access_token"`
	Expires_in         string `json:"expires_in"`
	Refresh_expires_in string `json:"refresh_expires_in"`
	Refresh_token      string `json:"refresh_token"`
	Token_type         string `json:"token_type"`
	Id_token           string `json:"id_token"`
	Not_before_policy  string `json:"not-before-policy"`
	Session_state      string `json:"session_state"`
	Scope              string `json:"scope"`
}

type payload struct {
	Exp            int      `json:"exp"`
	Iat            int      `json:"iat"`
	Jti            string   `json:"jti"`
	Iss            string   `json:"iss"`
	Aud            string   `json:"aud"`
	Sub            string   `json:"sub"`
	Typ            string   `json:"typ"`
	Azp            string   `json:"azp"`
	SessionState   string   `json:"session_state"`
	Acr            string   `json:"acr"`
	AllowedOrigins []string `json:"allowed-origins"`
	RealmAccess    struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	ResourceAccess struct {
		Account struct {
			Roles []string `json:"roles"`
		} `json:"account"`
	} `json:"resource_access"`
	Scope             string `json:"scope"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	GivenName         string `json:"given_name"`
	FamilyName        string `json:"family_name"`
}

type authorizationReq struct {
	Sub string `json:"sub"`
}

var env envList

func init() {
	env = envList{
		Port:          os.Getenv("APP_PORT"),
		KeyCloakUrl:   os.Getenv("KEY_URL"),
		Client_id:     os.Getenv("CLIENT_ID"),
		Client_secret: os.Getenv("CLIENT_SECRET"),
		Serivce_url:   os.Getenv("SVC_URL"),
	}
}

func main() {

	port := env.Port

	fmt.Println("Running web server....")
	http.HandleFunc("/", apiMakerHandler(homeHandler))
	http.HandleFunc("/login", apiMakerHandler(loginHandler))
	http.HandleFunc("/authorization", apiMakerHandler(authorizationHandler))
	http.HandleFunc("/externalservice", apiMakerHandler(externalHandler))
	http.ListenAndServe(":"+port, nil)
}

func apiMakerHandler(fn func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fn(w, r)
	}
}

var templates = template.Must(template.ParseFiles("view/login.html"))

func homeHandler(w http.ResponseWriter, r *http.Request) {
	err := templates.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		fmt.Println("parse error !!", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {

	username := r.FormValue("username")
	password := r.FormValue("password")

	tb, err := getAccessToken(username, password)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	fmt.Println(string(tb))

	var tres token

	err = json.Unmarshal(tb, &tres)
	sub, err := getSub(tres.Access_token)
	_, err = forwardToExernal(sub, tres.Access_token)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := response{
		Result:  "OK",
		Message: "Hello Go World",
		ApiName: "login",
	}
	output, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}

func getAccessToken(username string, password string) (r []byte, err error) {

	key_url := env.KeyCloakUrl
	client_id := env.Client_id
	secret := env.Client_secret

	//fmt.Println(key_url, client_id, secret, username, password)

	values := url.Values{}
	values.Set("grant_type", "password")
	values.Add("client_id", client_id)
	values.Add("client_secret", secret)
	values.Add("username", username)
	values.Add("password", password)
	values.Add("scope", "openid")

	req, err := http.NewRequest(
		"POST",
		key_url,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return nil, err
	}

	// Content-Type 設定
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	r, err = ioutil.ReadAll(resp.Body)
	return r, nil
}

func getSub(jwt string) (sub string, err error) {

	fmt.Println("access_token", jwt)

	hCS, err := jwtdecode.JwtDecode.DecomposeFB(jwt)

	payload, err := jwtdecode.JwtDecode.DecodeClaimFB(hCS[1])
	if err != nil {
		fmt.Println("error:", err)
		return "", err
	}

	return payload.Subject, nil
}

func forwardToExernal(sub, access_token string) (r []byte, err error) {

	svc_url := env.Serivce_url

	values := url.Values{}
	values.Set("Sub", sub)

	req, err := http.NewRequest(
		"POST",
		svc_url,
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return nil, err
	}

	// Content-Type 設定
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+access_token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	r, err = ioutil.ReadAll(resp.Body)
	return r, nil
}

func authorizationHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Println("received authorization")

	bufbody := new(bytes.Buffer)
	bufbody.ReadFrom(r.Body)
	body := bufbody.String()

	fmt.Println("headers")
	fmt.Println("Authorization", r.Header.Get("Authorization"))
	fmt.Println("body")
	fmt.Println(body)

	res := response{
		Result:  "OK",
		Message: "Hello Go World",
		ApiName: "authorization",
	}
	output, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}
func externalHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("received externalService")

	bufbody := new(bytes.Buffer)
	bufbody.ReadFrom(r.Body)
	body := bufbody.String()

	fmt.Println("headers")
	fmt.Println("Authorization", r.Header.Get("Authorization"))
	fmt.Println("body")
	fmt.Println(body)

	res := response{
		Result:  "OK",
		Message: "Hello Go World",
		ApiName: "externalService",
	}
	output, _ := json.Marshal(res)
	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}
