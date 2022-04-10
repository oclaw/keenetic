package keenetic

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

const (
	CHALLENGE_HEADER = "X-NDM-CHALLENGE"
	REALM_HEADER     = "X-NDM-REALM"
)

type Client struct {
	httpClient *http.Client
	baseUri    string
	cookie     []*http.Cookie
	scheme     string
}

type authRequest struct {
	Login string `json:"login"`
	Key   string `json:"password"`
}

func NewClient(baseUri, login, password string) (*Client, error) {

	httpApi := &http.Client{}

	url, err := url.Parse(baseUri)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base Keenetic URI, error: %s", err.Error())
	}
	url.Path = "/auth"

	res, err := httpApi.Get(url.String())
	if err != nil {
		return nil, fmt.Errorf("failed to GET /auth, internal error: %s", err.Error())
	}

	client := &Client{
		httpClient: httpApi,
		baseUri:    url.Host,
		scheme:     url.Scheme,
	}

	if res.StatusCode == http.StatusOK {
		return client, nil
	}

	if res.StatusCode == http.StatusUnauthorized {
		if err = client.auth(res, login, password); err != nil {
			return nil, err
		}
		return client, nil
	}

	return nil, fmt.Errorf("unexpected status code on GET /auth, code: %d", res.StatusCode)
}

func (client *Client) createRequest(method, contentType, url string, data io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, data)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for _, cookie := range client.cookie {
		req.AddCookie(cookie)
	}
	return req, nil
}

func (client *Client) execRequest(method, contentType, url string, data io.Reader) (*http.Response, error) {
	req, err := client.createRequest(method, contentType, url, data)
	if err != nil {
		return nil, fmt.Errorf("failed to create request, internal error: %s", err.Error())
	}
	return client.httpClient.Do(req)
}

func (client *Client) getUrl(path string) *url.URL {
	return &url.URL{
		Scheme: client.scheme,
		Host:   client.baseUri,
		Path:   path,
	}
}

func getAuthHash(login, password, token, realm string) string {
	passwordHasher := md5.New()
	tokenHasher := sha256.New()
	io.WriteString(passwordHasher, fmt.Sprintf("%s:%s:%s", login, realm, password))
	pwdMd5 := fmt.Sprintf("%x", passwordHasher.Sum(nil))
	io.WriteString(tokenHasher, fmt.Sprintf("%s%s", token, pwdMd5))
	return fmt.Sprintf("%x", tokenHasher.Sum(nil))
}

func (client *Client) auth(authData *http.Response, login, password string) error {
	token := authData.Header.Get(CHALLENGE_HEADER)
	realm := authData.Header.Get(REALM_HEADER)

	url := client.getUrl("/auth")

	reqData := authRequest{
		Login: login,
		Key:   getAuthHash(login, password, token, realm),
	}

	client.cookie = authData.Cookies()

	json, err := json.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("failed to create auth request content, internal error: %s", err.Error())
	}

	res, err := client.execRequest(http.MethodPost, "application/json", url.String(), bytes.NewReader(json))
	if err != nil {
		return fmt.Errorf("failed to receive auth response, internal error: %s", err.Error())
	}

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("bad auth response, status code: %d", res.StatusCode)
	}
	return nil
}

func (client *Client) Get(path string) (*http.Response, error) {
	return client.execRequest(http.MethodGet, "", client.getUrl(path).String(), nil)
}

func (client *Client) Post(path string, data io.Reader) (*http.Response, error) {
	// TODO: customize content type?
	return client.execRequest(http.MethodPost, "application/json", client.getUrl(path).String(), data)
}
