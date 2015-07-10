package main

import (
	"fmt"
	"os"

	"github.com/hashicorp/vault/api"
)

func main() {
	client, err := api.NewClient(&api.Config{
		Address: os.Getenv("VAULT_ADDR"),
	})
	if err != nil {
		panic(err)
	}
	if client == nil {
		panic("Returned Vault client was nil")
	}
	client.SetToken(os.Getenv("TEMP_TOKEN"))

	secret, err := client.Logical().Read("auth/token/lookup-self")
	if err != nil {
		panic(err)
	}
	if secret == nil {
		panic("Returned secret was nil")
	}
	metaInt, ok := secret.Data["meta"]
	if !ok {
		panic("Did not get metadata in response")
	}
	meta, ok := metaInt.(map[string]interface{})
	if !ok {
		panic(fmt.Sprintf("Could not convert meta interface to map, got %+v", secret))
	}
	permTokenLoc, ok := meta["permtoken"]
	if !ok {
		panic("No permtoken found in metadata")
	}
	permToken := permTokenLoc.(string)

	secret, err = client.Logical().Read("secret/pomltokens/" + permToken)
	if err != nil {
		panic(err)
	}
	if secret == nil {
		panic("Returned secret was nil")
	}
	token, ok := secret.Data["token"]
	if !ok {
		panic("No token found in metadata")
	}

	_, err = client.Logical().Delete("secret/pomltokens/" + permToken)
	if err != nil {
		panic(err)
	}

	fmt.Println(token)
}
