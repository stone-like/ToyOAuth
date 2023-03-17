package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Client struct {
	ClientId     string
	ClientName   string
	RedirectUris []string
}

func NewClient(clientId string, clientName string, redirectUris []string) *Client {
	return &Client{
		ClientId:     clientId,
		ClientName:   clientName,
		RedirectUris: redirectUris,
	}
}

func (c *Client) isValidRedirectUri(redirectUri string) bool {
	for _, uri := range c.RedirectUris {
		if uri == redirectUri {
			return true
		}
	}

	return false
}

type User struct {
	userId    string
	loginName string
	password  string
}

func NewUser(userId, loginName, password string) *User {
	return &User{
		userId:    userId,
		loginName: loginName,
		password:  password,
	}
}

//もしredirectUriが認可コードリクエストで送られてきたら、
//redirectUriは認可コードリクエストで送られてきたものと、アクセストークンリクエストで送られてきたものが同一でなければならない

//認可コードの寿命は最大10分

// buf := bytes.NewBufferString(data.Client.GetID())
// 	buf.WriteString(data.UserID)
// 	token := uuid.NewMD5(uuid.Must(uuid.NewRandom()), buf.Bytes())
// 	code := base64.URLEncoding.EncodeToString([]byte(token.String()))
// 	code = strings.ToUpper(strings.TrimRight(code, "="))
//ランダムの生成はclient,userの情報を上記みたいに入れた方が良さそう

func generateRandom() string {

	code := base64.URLEncoding.EncodeToString([]byte(uuid.Must(uuid.NewRandom()).String()))
	code = strings.ToUpper(strings.TrimRight(code, "="))

	return code
}

type AuthorizationCode struct {
	value       string
	userId      string
	clientId    string
	scopes      []string
	redirectUri string
	expires_at  time.Time
}

func NewAuthorizationCode(userId, clientId string, scopes []string, redirectUri string, expires_at time.Time) *AuthorizationCode {

	return &AuthorizationCode{
		value:       generateRandom(),
		userId:      userId,
		clientId:    clientId,
		scopes:      scopes,
		redirectUri: redirectUri,
		expires_at:  expires_at,
	}
}

type AccessToken struct {
	value      string
	userId     string
	clientId   string
	scopes     []string
	expires_at time.Time
}

func NewAccessToken(userId, clientId string, scopes []string, expires_at time.Time) *AccessToken {
	return &AccessToken{
		value:      generateRandom(),
		userId:     userId,
		clientId:   clientId,
		scopes:     scopes,
		expires_at: expires_at,
	}
}

type ResponseType struct {
	value string
}

func (r ResponseType) String() string {
	return r.value
}

var (
	Code = ResponseType{"code"}
)

var (
	ErrInvalidResponseType = errors.New("invalidResponseErr")
	ErrInvalidUser         = errors.New("invalidUserError")
)

func checkResponseType(resonseType string) error {
	switch resonseType {
	case Code.value:
		return nil
	}

	return ErrInvalidResponseType
}

var redirectUri = "http://example.com"

var clientStore = []*Client{
	NewClient("1", "MyClient", []string{redirectUri}),
}

var userStore = []*User{
	NewUser("1", "test", "test"),
}

var authorizationCodeStore = make(map[string]*AuthorizationCode)

var accessTokenStore = make(map[string]*AccessToken)

const (
	AUTHORIZATION_CODE_DURATION = 600
	ACCESS_TOKEN_DURATION       = 86400
)

func lookUpClient(clientId string) (*Client, bool) {
	for _, client := range clientStore {
		if client.ClientId == clientId {
			return client, true
		}
	}

	return &Client{}, false
}

//scopeは""、"AAA"、"AAA BBB"複数の場合は空白区切り
//""の場合は[]stringが返る
func filterScopes(scope string) []string {
	return strings.Split(strings.Trim(scope, " "), " ")
}

//Sessionにブラウザごとの情報を保持
func AuthorizeCode(c *gin.Context) {

	session := sessions.Default(c)

	//clientId
	clientId, exists := c.GetQuery("client_id")

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "client_id not extsts"})
		return
	}

	client, exists := lookUpClient(clientId)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "client_id is wrong"})
		return
	}

	//redirectUri
	redirectUri, exists := c.GetQuery("redirect_uri")

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "redirect_uri not exists"})
		return
	}

	if !client.isValidRedirectUri(redirectUri) {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "redirect_uri is wrong"})
		return
	}

	//responce_type
	//今回は認可コードフローのみ実装
	responseType, exists := c.GetQuery("response_type")

	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "response_type not exists"})
		return
	}

	if err := checkResponseType(responseType); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "response_type is wrong"})
		return
	}

	//state
	state := c.Query("state")

	//scope
	scopeString := c.Query("scope")
	scopes := filterScopes(scopeString)

	//後で使用するのでsessionに保存

	jsonedClient, err := json.Marshal(client)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
		return
	}

	session.Set("client", jsonedClient)
	session.Set("state", state)
	session.Set("scopes", scopeString)
	session.Set("redirectUri", redirectUri)
	session.Save()

	c.HTML(200, "authorization_page.html", gin.H{
		"client_name": client.ClientName,
		"scopes":      scopes,
	})
	return

}

func createBaseRedirectLocation(redirectUri, state string) string {
	return fmt.Sprintf("%s?state=%s", redirectUri, state)
}

func customRedirectLocation(baseRedirectUri string, queries map[string]string) string {

	var builder strings.Builder

	builder.WriteString(baseRedirectUri)
	builder.WriteString("&")

	for key, value := range queries {
		builder.WriteString(key)
		builder.WriteString("=")
		builder.WriteString(value)
		builder.WriteString("&")
	}

	return strings.TrimRight(builder.String(), "&")
}

func findUser(loginName, password string) (*User, error) {
	for _, user := range userStore {
		if user.loginName == loginName && user.password == password {
			return user, nil
		}
	}

	return &User{}, ErrInvalidUser
}

func Decision(c *gin.Context) {
	session := sessions.Default(c)

	clientBytes := session.Get("client").([]byte)
	client := &Client{}
	err := json.Unmarshal(clientBytes, client)
	if err != nil {
		c.Redirect(http.StatusFound, customRedirectLocation(
			redirectUri,
			map[string]string{
				"error":             "access_denied",
				"error_description": "marshal error",
			},
		))
		return
	}

	scopeString, ok := session.Get("state").(string)
	if !ok {
		c.Redirect(http.StatusFound, customRedirectLocation(
			redirectUri,
			map[string]string{
				"error":             "access_denied",
				"error_description": "session storage error",
			},
		))
		return
	}

	scopes := filterScopes(scopeString)
	state := session.Get("state").(string)
	redirectUri := session.Get("redirectUri").(string)

	redirectlocation := createBaseRedirectLocation(redirectUri, state)

	_, exists := c.GetPostForm("approved")
	if !exists {
		c.Redirect(http.StatusFound, customRedirectLocation(
			redirectlocation,
			map[string]string{
				"error":             "access_denied",
				"error_description": "The request was not approved",
			},
		))
		return
	}

	user, err := findUser(c.PostForm("login_name"), c.PostForm("password"))
	if err != nil {
		c.Redirect(http.StatusFound, customRedirectLocation(
			redirectlocation,
			map[string]string{
				"error":             "access_denied",
				"error_description": "user authentication failed",
			},
		))
		return
	}

	expires_at := time.Now().Add(AUTHORIZATION_CODE_DURATION)
	code := NewAuthorizationCode(user.userId, client.ClientId, scopes, redirectUri, expires_at)

	authorizationCodeStore[code.value] = code

	c.Redirect(http.StatusFound, customRedirectLocation(
		redirectlocation,
		map[string]string{
			"code": code.value,
		},
	))

	return

}

func GetPostParam(c *gin.Context, param string) (string, error) {
	value, exists := c.GetPostForm(param)
	if !exists {
		return "", fmt.Errorf("invalid request,%s is missing", param)
	}

	return value, nil
}

func Token(c *gin.Context) {
	grantType, err := GetPostParam(c, "grant_type")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
		return
	}

	//ここenumとかでチェックした方が良いし、マジックナンバー(マジックストリング)は使わない方がいい
	if grantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "unsupported grant type"})
		return
	}

	codeValue, err := GetPostParam(c, "code")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
		return
	}

	code, exists := authorizationCodeStore[codeValue]
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "autorization code is wrong"})
		return
	}

	if code.expires_at.After(time.Now()) {
		delete(authorizationCodeStore, codeValue)
		c.JSON(http.StatusBadRequest, gin.H{"msg": "autorization code has already expied"})
		return
	}

	redirectUri, err := GetPostParam(c, "redirect_uri")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
		return
	}

	if redirectUri != code.redirectUri {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "redirect_uri is wrong"})
		return
	}

	clientId, err := GetPostParam(c, "client_id")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
		return
	}

	if clientId != code.clientId {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "client_id is wrong"})
		return
	}

	//アクセストークンを生成
	expiresAt := time.Now().Add(ACCESS_TOKEN_DURATION)

	token := NewAccessToken(code.userId, code.clientId, code.scopes, expiresAt)
	accessTokenStore[token.value] = token

	//使用済みの認可コードは削除
	delete(authorizationCodeStore, codeValue)

	c.JSON(http.StatusOK, gin.H{
		"access_token": token.value,
		"token_type":   "Bearer",
		"expires_in":   ACCESS_TOKEN_DURATION,
		"scope":        strings.Join(token.scopes, " "),
	})

	return
}

func SetSession(router *gin.Engine) {
	store := cookie.NewStore([]byte("secret"))
	router.Use(sessions.Sessions("mysession", store))
}

func SetRoute(router *gin.Engine) {
	router.GET("/auth", AuthorizeCode)
	router.POST("/decision", Decision)
	router.POST("/token", Token)

}

func main() {
	router := gin.Default()

	router.LoadHTMLGlob("templates/*.html")
	SetSession(router)
	SetRoute(router)

	router.Run()
}
