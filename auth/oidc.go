package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	fbErrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodOIDCAuth is used to identify OIDC auth.
const MethodOIDCAuth settings.AuthMethod = "oidc"

// OIDCConfig holds the OIDC configuration.
type OIDCConfig struct {
	ProviderURL    string            `json:"providerURL" yaml:"providerURL"`
	ClientID       string            `json:"clientID" yaml:"clientID"`
	ClientSecret   string            `json:"clientSecret" yaml:"clientSecret"`
	RedirectURI    string            `json:"redirectURI" yaml:"redirectURI"`
	Scopes         []string          `json:"scopes" yaml:"scopes"`
	ClaimMappings  ClaimMappings     `json:"claimMappings" yaml:"claimMappings"`
	AutoCreateUser bool              `json:"autoCreateUser" yaml:"autoCreateUser"`
	GroupMappings  map[string]string `json:"groupMappings" yaml:"groupMappings"`
}

// ClaimMappings defines how OIDC claims map to user fields.
type ClaimMappings struct {
	Username    string `json:"username" yaml:"username"`
	Email       string `json:"email" yaml:"email"`
	DisplayName string `json:"displayName" yaml:"displayName"`
	Groups      string `json:"groups" yaml:"groups"`
}

// OIDCAuth is an OIDC implementation of an Auther.
type OIDCAuth struct {
	Config   *OIDCConfig `json:"config" yaml:"config"`
	provider *oidc.Provider
	oauth2Config *oauth2.Config
}

// Auth authenticates the user via OIDC callback.
func (a *OIDCAuth) Auth(r *http.Request, usr users.Store, setting *settings.Settings, srv *settings.Server) (*users.User, error) {
	// This method handles the OIDC callback
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	
	if code == "" {
		return nil, fmt.Errorf("missing authorization code")
	}

	// Verify state parameter (should be validated against session)
	if state == "" {
		return nil, fmt.Errorf("missing state parameter")
	}

	// Initialize provider and oauth2 config if not already done
	if err := a.initializeProvider(r.Context()); err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	// Exchange code for token
	token, err := a.oauth2Config.Exchange(r.Context(), code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for token: %w", err)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("no id_token found in token response")
	}

	// Verify ID token
	verifier := a.provider.Verifier(&oidc.Config{ClientID: a.Config.ClientID})
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	// Map claims to user
	username := a.extractClaim(claims, a.Config.ClaimMappings.Username, "sub")
	if username == "" {
		return nil, fmt.Errorf("username claim not found")
	}

	// Try to get existing user
	user, err := usr.Get(srv.Root, username)
	if err != nil && !errors.Is(err, fbErrors.ErrNotExist) {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Create user if doesn't exist and auto-creation is enabled
	if errors.Is(err, fbErrors.ErrNotExist) {
		if !a.Config.AutoCreateUser {
			return nil, fmt.Errorf("user %s does not exist and auto-creation is disabled", username)
		}

		user, err = a.createUserFromClaims(claims, username, usr, setting, srv)
		if err != nil {
			return nil, fmt.Errorf("failed to create user from claims: %w", err)
		}
	}

	return user, nil
}

// LoginPage tells that OIDC auth requires a login page for the redirect flow.
func (a *OIDCAuth) LoginPage() bool {
	return true
}

// GetAuthURL returns the OIDC authorization URL.
func (a *OIDCAuth) GetAuthURL(state string) (string, error) {
	if err := a.initializeProvider(context.Background()); err != nil {
		return "", fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	return a.oauth2Config.AuthCodeURL(state), nil
}

// initializeProvider initializes the OIDC provider and oauth2 config.
func (a *OIDCAuth) initializeProvider(ctx context.Context) error {
	if a.provider != nil && a.oauth2Config != nil {
		return nil
	}

	if a.Config == nil {
		return fmt.Errorf("OIDC config is not set")
	}

	provider, err := oidc.NewProvider(ctx, a.Config.ProviderURL)
	if err != nil {
		return fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	scopes := a.Config.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}

	oauth2Config := &oauth2.Config{
		ClientID:     a.Config.ClientID,
		ClientSecret: a.Config.ClientSecret,
		RedirectURL:  a.Config.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	a.provider = provider
	a.oauth2Config = oauth2Config

	return nil
}

// extractClaim extracts a claim value with fallback.
func (a *OIDCAuth) extractClaim(claims map[string]interface{}, claimName, fallback string) string {
	if claimName != "" {
		if val, ok := claims[claimName]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}

	if fallback != "" {
		if val, ok := claims[fallback]; ok {
			if str, ok := val.(string); ok {
				return str
			}
		}
	}

	return ""
}

// createUserFromClaims creates a new user from OIDC claims.
func (a *OIDCAuth) createUserFromClaims(claims map[string]interface{}, username string, usr users.Store, setting *settings.Settings, srv *settings.Server) (*users.User, error) {
	const randomPasswordLength = settings.DefaultMinimumPasswordLength + 10
	pwd, err := users.RandomPwd(randomPasswordLength)
	if err != nil {
		return nil, err
	}

	hashedRandomPassword, err := users.ValidateAndHashPwd(pwd, setting.MinimumPasswordLength)
	if err != nil {
		return nil, err
	}

	user := &users.User{
		Username:     username,
		Password:     hashedRandomPassword,
		LockPassword: true, // OIDC users shouldn't change password locally
	}

	// Apply default settings
	setting.Defaults.Apply(user)

	// Set email if available
	if email := a.extractClaim(claims, a.Config.ClaimMappings.Email, "email"); email != "" {
		// Note: users.User doesn't have Email field, but we could extend it if needed
		log.Printf("OIDC user %s has email: %s", username, email)
	}

	// Create user home directory if enabled
	var userHome string
	if setting.CreateUserDir {
		userHome, err = setting.MakeUserDir(user.Username, user.Scope, srv.Root)
		if err != nil {
			return nil, fmt.Errorf("failed to create user home directory: %w", err)
		}
		user.Scope = userHome
	}

	// Save the user
	err = usr.Save(user)
	if err != nil {
		return nil, fmt.Errorf("failed to save user: %w", err)
	}

	log.Printf("Created OIDC user: %s, home dir: [%s]", user.Username, userHome)
	return user, nil
}

// GenerateState generates a random state parameter for OIDC flow.
func GenerateState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}