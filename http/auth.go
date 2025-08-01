package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/request"

	"github.com/filebrowser/filebrowser/v2/auth"
	fbErrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/users"
)

const (
	DefaultTokenExpirationTime = time.Hour * 2
)

type userInfo struct {
	ID           uint              `json:"id"`
	Locale       string            `json:"locale"`
	ViewMode     users.ViewMode    `json:"viewMode"`
	SingleClick  bool              `json:"singleClick"`
	Perm         users.Permissions `json:"perm"`
	Commands     []string          `json:"commands"`
	LockPassword bool              `json:"lockPassword"`
	HideDotfiles bool              `json:"hideDotfiles"`
	DateFormat   bool              `json:"dateFormat"`
	Username     string            `json:"username"`
}

type authToken struct {
	User userInfo `json:"user"`
	jwt.RegisteredClaims
}

type extractor []string

func (e extractor) ExtractToken(r *http.Request) (string, error) {
	token, _ := request.HeaderExtractor{"X-Auth"}.ExtractToken(r)

	// Checks if the token isn't empty and if it contains two dots.
	// The former prevents incompatibility with URLs that previously
	// used basic auth.
	if token != "" && strings.Count(token, ".") == 2 {
		return token, nil
	}

	auth := r.URL.Query().Get("auth")
	if auth != "" && strings.Count(auth, ".") == 2 {
		return auth, nil
	}

	if r.Method == http.MethodGet {
		cookie, _ := r.Cookie("auth")
		if cookie != nil && strings.Count(cookie.Value, ".") == 2 {
			return cookie.Value, nil
		}
	}

	return "", request.ErrNoTokenInRequest
}

func withUser(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		keyFunc := func(_ *jwt.Token) (interface{}, error) {
			return d.settings.Key, nil
		}

		var tk authToken
		token, err := request.ParseFromRequest(r, &extractor{}, keyFunc, request.WithClaims(&tk))

		if err != nil || !token.Valid {
			return http.StatusUnauthorized, nil
		}

		expired := !tk.VerifyExpiresAt(time.Now().Add(time.Hour), true)
		updated := tk.IssuedAt != nil && tk.IssuedAt.Unix() < d.store.Users.LastUpdate(tk.User.ID)

		if expired || updated {
			w.Header().Add("X-Renew-Token", "true")
		}

		d.user, err = d.store.Users.Get(d.server.Root, tk.User.ID)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		return fn(w, r, d)
	}
}

func withAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		return fn(w, r, d)
	})
}

func loginHandler(tokenExpireTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		auther, err := d.store.Auth.Get(d.settings.AuthMethod)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		user, err := auther.Auth(r, d.store.Users, d.settings, d.server)
		switch {
		case errors.Is(err, os.ErrPermission):
			return http.StatusForbidden, nil
		case err != nil:
			return http.StatusInternalServerError, err
		}

		return printToken(w, r, d, user, tokenExpireTime)
	}
}

type signupBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var signupHandler = func(_ http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.settings.Signup {
		return http.StatusMethodNotAllowed, nil
	}

	if r.Body == nil {
		return http.StatusBadRequest, nil
	}

	info := &signupBody{}
	err := json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if info.Password == "" || info.Username == "" {
		return http.StatusBadRequest, nil
	}

	user := &users.User{
		Username: info.Username,
	}

	d.settings.Defaults.Apply(user)

	pwd, err := users.ValidateAndHashPwd(info.Password, d.settings.MinimumPasswordLength)
	if err != nil {
		return http.StatusBadRequest, err
	}

	user.Password = pwd
	if d.settings.CreateUserDir {
		user.Scope = ""
	}

	userHome, err := d.settings.MakeUserDir(user.Username, user.Scope, d.server.Root)
	if err != nil {
		log.Printf("create user: failed to mkdir user home dir: [%s]", userHome)
		return http.StatusInternalServerError, err
	}
	user.Scope = userHome
	log.Printf("new user: %s, home dir: [%s].", user.Username, userHome)

	err = d.store.Users.Save(user)
	if errors.Is(err, fbErrors.ErrExist) {
		return http.StatusConflict, err
	} else if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

type oidcConfigResponse struct {
	Enabled bool   `json:"enabled"`
	AuthURL string `json:"authURL,omitempty"`
}

var oidcConfigHandler = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	// Check if OIDC is enabled
	auther, err := d.store.Auth.Get(d.settings.AuthMethod)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	response := oidcConfigResponse{
		Enabled: false,
	}

	if d.settings.AuthMethod == "oidc" {
		if oidcAuth, ok := auther.(*auth.OIDCAuth); ok && oidcAuth.Config != nil {
			// Generate state parameter and store it (in production, you'd store this in session/cache)
			state, err := auth.GenerateState()
			if err != nil {
				return http.StatusInternalServerError, err
			}

			authURL, err := oidcAuth.GetAuthURL(state)
			if err != nil {
				return http.StatusInternalServerError, err
			}

			response.Enabled = true
			response.AuthURL = authURL
		}
	}

	return renderJSON(w, r, response)
}

var oidcLoginHandler = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	// Check if OIDC is enabled
	if d.settings.AuthMethod != "oidc" {
		return http.StatusNotFound, nil
	}

	auther, err := d.store.Auth.Get(d.settings.AuthMethod)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	oidcAuth, ok := auther.(*auth.OIDCAuth)
	if !ok || oidcAuth.Config == nil {
		return http.StatusInternalServerError, errors.New("OIDC not configured")
	}

	// Generate state parameter
	state, err := auth.GenerateState()
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// In a production environment, you would store the state in a session or cache
	// associated with the user's session to validate it in the callback

	authURL, err := oidcAuth.GetAuthURL(state)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	// Redirect to OIDC provider
	http.Redirect(w, r, authURL, http.StatusFound)
	return 0, nil
}

func oidcCallbackHandler(tokenExpireTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		// Check if OIDC is enabled
		if d.settings.AuthMethod != "oidc" {
			return http.StatusNotFound, nil
		}

		auther, err := d.store.Auth.Get(d.settings.AuthMethod)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		user, err := auther.Auth(r, d.store.Users, d.settings, d.server)
		switch {
		case errors.Is(err, os.ErrPermission):
			return http.StatusForbidden, nil
		case err != nil:
			return http.StatusInternalServerError, err
		}

		// Generate JWT token
		claims := &authToken{
			User: userInfo{
				ID:           user.ID,
				Locale:       user.Locale,
				ViewMode:     user.ViewMode,
				SingleClick:  user.SingleClick,
				Perm:         user.Perm,
				LockPassword: user.LockPassword,
				Commands:     user.Commands,
				HideDotfiles: user.HideDotfiles,
				DateFormat:   user.DateFormat,
				Username:     user.Username,
			},
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpireTime)),
				Issuer:    "File Browser",
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signed, err := token.SignedString(d.settings.Key)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		// Set cookie and redirect to frontend with token parameter
		http.SetCookie(w, &http.Cookie{
			Name:     "auth",
			Value:    signed,
			Path:     "/",
			HttpOnly: false, // Allow JavaScript access
			SameSite: http.SameSiteStrictMode,
		})

		// Redirect to a special URL that the frontend can handle
		redirectURL := fmt.Sprintf("/?token=%s", signed)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return 0, nil
	}
}

func renewHandler(tokenExpireTime time.Duration) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		w.Header().Set("X-Renew-Token", "false")
		return printToken(w, r, d, d.user, tokenExpireTime)
	})
}

func printToken(w http.ResponseWriter, _ *http.Request, d *data, user *users.User, tokenExpirationTime time.Duration) (int, error) {
	claims := &authToken{
		User: userInfo{
			ID:           user.ID,
			Locale:       user.Locale,
			ViewMode:     user.ViewMode,
			SingleClick:  user.SingleClick,
			Perm:         user.Perm,
			LockPassword: user.LockPassword,
			Commands:     user.Commands,
			HideDotfiles: user.HideDotfiles,
			DateFormat:   user.DateFormat,
			Username:     user.Username,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpirationTime)),
			Issuer:    "File Browser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(d.settings.Key)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(signed)); err != nil {
		return http.StatusInternalServerError, err
	}
	return 0, nil
}
