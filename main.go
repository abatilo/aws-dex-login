package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

const (
	// FlagPort is the port to listen on
	FlagPort = "port"

	// FlagClientID is the oidc client ID
	FlagClientID = "client-id"

	// FlagIssuer is the oidc issuer
	FlagIssuer = "issuer"

	// FlagRoleARN is the role ARN to assume
	FlagRoleARN = "role-arn"

	// FlagSessionDuration is the duration of the session
	FlagSessionDuration = "session-duration"
)

// generateRandomString generates a random string of the given length
// Used for generating state
func generateRandomString(length int) string {
	seededRand := rand.New(rand.NewSource(time.Now().UnixNano()))
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func main() {
	viper.SetEnvPrefix("ADL_")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	viper.AutomaticEnv()

	run := func(cmd *cobra.Command, args []string) {
		port := viper.GetInt(FlagPort)
		clientID := viper.GetString(FlagClientID)
		redirectURI := fmt.Sprintf("http://localhost:%d", port)
		issuer := viper.GetString(FlagIssuer)
		roleARN := viper.GetString(FlagRoleARN)
		sessionDuration := viper.GetInt(FlagSessionDuration)

		if clientID == "" {
			log.Println("client-id is required")
			cmd.Help()
			return
		}

		if issuer == "" {
			log.Println("issuer is required")
			cmd.Help()
			return
		}

		if roleARN == "" {
			log.Println("role-arn is required")
			cmd.Help()
			return
		}

		provider, err := oidc.NewProvider(context.Background(), issuer)
		if err != nil {
			log.Fatalln(fmt.Errorf("Failed to get oidc provider: %w", err))
		}

		// Generate random string for state
		state := uuid.New().String()

		var supportedScopesClaim struct {
			SupportedScopes []string `json:"scopes_supported"`
		}
		if err := provider.Claims(&supportedScopesClaim); err != nil {
			log.Fatalln(fmt.Errorf("Failed to get supported scopes: %w", err))
		}

		oauth2Config := &oauth2.Config{
			ClientID:    clientID,
			Endpoint:    provider.Endpoint(),
			RedirectURL: redirectURI,
			Scopes:      supportedScopesClaim.SupportedScopes,
		}

		// Silence browser package to prevent malforming stdout
		browser.Stderr = ioutil.Discard
		browser.Stdout = ioutil.Discard
		browser.OpenURL(fmt.Sprintf("%s/auth?grant_type=authorization_code&response_type=code&client_id=%s&redirect_uri=%s&scope=openid+email+groups+profile+offline_access&state=%s", issuer, clientID, redirectURI, state))

		done := make(chan struct{})
		mux := http.NewServeMux()

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			queryValues := r.URL.Query()
			queryState := queryValues.Get("state")
			queryCode := queryValues.Get("code")

			// Check for matching state
			if queryState != state {
				err := fmt.Errorf("State does not match: %s != %s", queryState, state)
				http.Error(w, err.Error(), http.StatusBadRequest)
				log.Fatalln(err)
			}

			// Handle the callback from the authorization server.
			token, err := oauth2Config.Exchange(context.Background(), queryCode, oauth2.AccessTypeOffline)
			if err != nil {
				err := fmt.Errorf("Failed to exchange token: %w", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				log.Fatalln(err)
			}

			// Extract the ID Token from OAuth2 token.
			rawIDToken, ok := token.Extra("id_token").(string)
			if !ok {
				err := fmt.Errorf("Failed to get id_token")
				http.Error(w, err.Error(), http.StatusBadRequest)
				log.Fatalln(err)
			}

			// Parse and verify ID Token payload.
			verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
			idToken, err := verifier.Verify(r.Context(), rawIDToken)
			if err != nil {
				err := fmt.Errorf("Failed to verify ID Token: %w", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				log.Fatalln(err)
			}

			// Extract custom identityClaims
			var identityClaims struct {
				Email             string `json:"email"`
				EmailVerified     bool   `json:"email_verified"`
				Name              string `json:"name"`
				PreferredUsername string `json:"preferred_username"`
			}
			if err := idToken.Claims(&identityClaims); err != nil {
				err := fmt.Errorf("Failed to get id token claims: %w", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				log.Fatalln(err)
			}

			awsSession := session.Must(session.NewSession())

			// Create a STS client from just a session.
			stsClient := sts.New(awsSession)
			input := &sts.AssumeRoleWithWebIdentityInput{
				DurationSeconds:  aws.Int64(int64(sessionDuration)),
				RoleArn:          aws.String(roleARN),
				RoleSessionName:  aws.String(identityClaims.Email),
				WebIdentityToken: aws.String(rawIDToken),
			}
			result, err := stsClient.AssumeRoleWithWebIdentity(input)

			credentials := map[string]interface{}{
				"Version":         1,
				"Expiration":      *result.Credentials.Expiration,
				"AccessKeyId":     *result.Credentials.AccessKeyId,
				"SecretAccessKey": *result.Credentials.SecretAccessKey,
				"SessionToken":    *result.Credentials.SessionToken,
			}

			// Print struct as json
			b, err := json.Marshal(credentials)
			if err != nil {
				err := fmt.Errorf("Failed to marshal credentials: %w", err)
				http.Error(w, err.Error(), http.StatusBadRequest)
				log.Fatalln(err)
			}
			fmt.Fprintf(w, "Login was successful. You can close this window.\n\n")
			fmt.Print(string(b))

			// Let the application know to exit
			defer close(done)
			return
		})

		srv := &http.Server{
			Addr:    fmt.Sprintf(":%d", port),
			Handler: mux,
		}

		go func() {
			// Will block until the channel is closed
			select {
			case <-done:
				// Do nothing
			case <-time.After(time.Second * 20):
				log.Fatalln("Timed out waiting for login")
			}
			// Will cause `ListenAndServe` to return
			srv.Shutdown(context.Background())
		}()

		srv.ListenAndServe()
	}

	cmd := &cobra.Command{
		Use:   "aws-dex-login",
		Short: "Retrieve credentials for using AWS via dex",
		Run:   run,
	}

	persistentFlags := cmd.PersistentFlags()
	persistentFlags.Int(FlagPort, 51515, "Port to listen on")
	persistentFlags.String(FlagIssuer, "", "OIDC issuer")
	persistentFlags.String(FlagClientID, "", "OIDC client ID")
	persistentFlags.String(FlagRoleARN, "", "AWS role ARN")
	persistentFlags.Int(FlagSessionDuration, 3600, "Session duration in seconds")
	viper.BindPFlag(FlagPort, persistentFlags.Lookup(FlagPort))
	viper.BindPFlag(FlagIssuer, persistentFlags.Lookup(FlagIssuer))
	viper.BindPFlag(FlagClientID, persistentFlags.Lookup(FlagClientID))
	viper.BindPFlag(FlagRoleARN, persistentFlags.Lookup(FlagRoleARN))
	viper.BindPFlag(FlagSessionDuration, persistentFlags.Lookup(FlagSessionDuration))

	cmd.Execute()
}
