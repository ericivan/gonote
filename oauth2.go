package main

import (
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	 "net/http"
	"fmt"
	"io/ioutil"
)

var GithubConfig = oauth2.Config{
	ClientID:     "",
	ClientSecret: "",
	Scopes:       []string{},
	Endpoint:     github.Endpoint,
}

var oauthstate = "state"

const htmlIndex = `<html><body>
<a href="/GithubLogin">Log in with Github</a>
</body></html>
`

func main() {
	http.HandleFunc("/", handleMain)

	http.HandleFunc("/GithubLogin", handlerLogin)

	http.HandleFunc("/api/oauth2/callback", handleGithubCallback)

	fmt.Println(http.ListenAndServe(":2333", nil))
}

func handleMain(w http.ResponseWriter,r *http.Request) {
	fmt.Fprintf(w, htmlIndex)
}

func handlerLogin(w http.ResponseWriter, r *http.Request) {
	url := GithubConfig.AuthCodeURL(oauthstate)

	fmt.Println(url)

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)

}


func handleGithubCallback(w http.ResponseWriter,r *http.Request) {
	state:=r.FormValue("state")


	if state!= oauthstate {
		fmt.Println("invalid oauth state")

		http.Redirect(w,r,"/",http.StatusTemporaryRedirect)
	}

	fmt.Println(state)

	code:=r.FormValue("code")


	token,err:=GithubConfig.Exchange(oauth2.NoContext, code)

	fmt.Println(token)


	if err!= nil {
		fmt.Printf("code exchange failed with %s \n", err)
		http.Redirect(w,r,"/",http.StatusTemporaryRedirect)
		return
	}

	response,err:=http.Get("https://api.github.com/user?access_token=" + token.AccessToken)

	defer response.Body.Close()

	contents,err:=ioutil.ReadAll(response.Body)

	fmt.Fprintf(w, "%s\n", contents)
}