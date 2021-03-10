package location

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/GoKillers/libsodium-go/cryptobox"
	"github.com/google/go-github/v33/github"
	"github.com/ovotech/cloud-key-rotator/pkg/cred"
	"golang.org/x/oauth2"
)

type GitHubActions struct {
	Org         string
	Repo        string
	KeyIDEnvVar string
	KeyEnvVar   string
}

func (gitHubActions GitHubActions) Write(serviceAccountName string, keyWrapper KeyWrapper, creds cred.Credentials) (updated UpdatedLocation, err error) {
	logger.Infof("Starting GitHub Actions env var updates, %s %s", gitHubActions.Org, gitHubActions.Repo)

	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: creds.GitHubToken},
	)
	tc := oauth2.NewClient(ctx, ts)

	client := github.NewClient(tc)

	var keyEnvVar string
	var idValue bool
	if keyEnvVar, err = getVarNameFromProvider(keyWrapper.KeyProvider, gitHubActions.KeyEnvVar, idValue); err != nil {
		return
	}

	if err = encryptAndUpdateSecret(ctx, client, gitHubActions.Org, gitHubActions.Repo, keyEnvVar, keyWrapper.Key); err != nil {
		return
	}

	var keyIDEnvVar string
	idValue = true
	if keyIDEnvVar, err = getVarNameFromProvider(keyWrapper.KeyProvider, gitHubActions.KeyIDEnvVar, idValue); err != nil {
		return
	}

	if len(keyIDEnvVar) > 0 {
		if err = encryptAndUpdateSecret(ctx, client, gitHubActions.Org, gitHubActions.Repo, keyIDEnvVar, keyWrapper.KeyID); err != nil {
			return
		}
	}

	updated = UpdatedLocation{
		LocationType: "GithubActions",
		LocationURI:  fmt.Sprintf("%s %s", gitHubActions.Org, gitHubActions.Repo),
		LocationIDs:  []string{keyEnvVar, keyIDEnvVar}}

	return updated, nil
}

func encryptAndUpdateSecret(ctx context.Context, client *github.Client, org string, repo string, envVarName string, envVarValue string) (err error) {
	var publicKey *github.PublicKey
	if publicKey, err = getPublicKey(ctx, client, org, repo); err != nil {
		return
	}

	var encryptedKey *github.EncryptedSecret
	if encryptedKey, err = encryptSecret(publicKey, envVarName, envVarValue); err != nil {
		return
	}

	if isOrgSecret(repo) {
		if _, err = client.Actions.CreateOrUpdateOrgSecret(ctx, org, encryptedKey); err != nil {
			return
		}
	} else {
		if _, err = client.Actions.CreateOrUpdateRepoSecret(ctx, org, repo, encryptedKey); err != nil {
			return
		}
	}
	return nil
}

func getPublicKey(ctx context.Context, client *github.Client, org string, repo string) (key *github.PublicKey, err error) {
	if isOrgSecret(repo) {
		if key, _, err = client.Actions.GetOrgPublicKey(ctx, org); err != nil {
			return
		}
	} else {
		if key, _, err = client.Actions.GetRepoPublicKey(ctx, org, repo); err != nil {
			return
		}
	}
	return key, nil
}

func encryptSecret(key *github.PublicKey, envVarName string, envVarValue string) (encryptedSecret *github.EncryptedSecret, err error) {
	var decodedPublicKey []byte
	if decodedPublicKey, err = base64.StdEncoding.DecodeString(key.GetKey()); err != nil {
		return nil, err
	}

	secretBytes := []byte(envVarValue)

	encryptedBytes, exit := cryptobox.CryptoBoxSeal(secretBytes, decodedPublicKey)
	if exit != 0 {
		return nil, errors.New("CryptoBoxSeal exited with non zero exit code")
	}

	encryptedSecretString := base64.StdEncoding.EncodeToString(encryptedBytes)

	encryptedSecret = &github.EncryptedSecret{
		Name:           envVarName,
		KeyID:          key.GetKeyID(),
		EncryptedValue: encryptedSecretString,
	}

	return encryptedSecret, nil
}

func isOrgSecret(repo string) bool {
	return repo == ""
}
