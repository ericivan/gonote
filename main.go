package main

import (
	"github.com/kataras/iris/sessions"
	"github.com/gorilla/securecookie"
	"github.com/kataras/iris"
	"github.com/kataras/iris/core/errors"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
	"os"
	"github.com/markbates/goth/providers/openidConnect"
	"sort"
)

var sessionManager *sessions.Sessions

func init() {

	cookieName := "mycustomsessionid"

	hashKey := []byte("the-big-and-secret-fash-key-here")
	blockKey := []byte("lot-secret-of-characters-big-too")

	secureCookie := securecookie.New(hashKey, blockKey)

	sessionManager = sessions.New(sessions.Config{
		Cookie: cookieName,
		Encode: secureCookie.Encode,
		Decode: secureCookie.Decode,
	})
}

var GetProviderName = func(ctx iris.Context) (string, error) {

	if p := ctx.URLParam("provider"); p != "" {
		return p, nil
	}

	if p := ctx.Params().Get("provider"); p != "" {
		return p, nil
	}

	if p := ctx.Values().GetString("provider"); p != "" {
		return p, nil
	}

	return "", errors.New("you must select a provider")

}

func GetAuthURL(ctx iris.Context) (string, error) {
	providerName, err := GetProviderName(ctx)
	if err != nil {
		return "", err
	}

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}
	sess, err := provider.BeginAuth(SetState(ctx))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}
	session := sessionManager.Start(ctx)
	session.Set(providerName, sess.Marshal())
	return url, nil
}

func BeginAuthHandler(ctx iris.Context) {
	url, err := GetAuthURL(ctx)
	if err != nil {
		ctx.StatusCode(iris.StatusBadRequest)
		ctx.Writef("%v", err)
		return
	}

	ctx.Redirect(url, iris.StatusTemporaryRedirect)
}

var SetState = func(ctx iris.Context) string {
	state := ctx.URLParam("state")
	if len(state) > 0 {
		return state
	}

	return "state"

}

var GetState = func(ctx iris.Context) string {
	return ctx.URLParam("state")
}

var CompleteUserAuth = func(ctx iris.Context) (goth.User, error) {
	providerName, err := GetProviderName(ctx)

	if err != nil {
		return goth.User{}, err
	}

	provider, err := goth.GetProvider(providerName)

	if err != nil {
		return goth.User{}, err
	}

	session := sessionManager.Start(ctx)

	value := session.GetString(providerName)

	if value == "" {
		return goth.User{}, errors.New("session value for " + providerName + " not found")
	}

	sess, err := provider.UnmarshalSession(value)

	if err != nil {
		return goth.User{}, err
	}

	user, err := provider.FetchUser(sess)

	if err == nil {
		return user, err
	}

	_, err = sess.Authorize(provider, ctx.Request().URL.Query())

	if err != nil {
		return goth.User{}, err
	}

	session.Set(providerName, sess.Marshal())

	return provider.FetchUser(sess)

}

func Logout(ctx iris.Context) error {
	providerName, err := GetProviderName(ctx)
	if err != nil {
		return err
	}
	session := sessionManager.Start(ctx)
	session.Delete(providerName)
	return nil
}

func main() {
	goth.UseProviders(
		github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "http://localhost:3000/auth/github/callback"),
	)

	openidConnected, _ := openidConnect.New(os.Getenv("OPENID_CONNECT_KEY"), os.Getenv("OPENID_CONNECT_SECRET"), "http://localhost:3000/auth/openid-connect/callback", os.Getenv("OPENID_CONNECT_DISCOVERY_URL"))

	if openidConnected != nil {
		goth.UseProviders(openidConnected)
	}

	m := make(map[string]string)

	m["github"] = "Github"

	var keys []string
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}

	app := iris.New()

	app.RegisterView(iris.HTML("./templates", ".html"))

	app.Get("/auth/{provider}/callback", func(ctx iris.Context) {
		user, err := CompleteUserAuth(ctx)

		if err != nil {
			ctx.StatusCode(iris.StatusInternalServerError)
			ctx.Writef("%v", err)
			return
		}

		ctx.ViewData("", user)

		if err := ctx.View("user.html"); err != nil {
			ctx.Writef("v", err)
		}
	})

	app.Get("/logout{provider}", func(ctx iris.Context) {
		Logout(ctx)

		ctx.Redirect("/", iris.StatusTemporaryRedirect)
	})

	app.Get("/", func(ctx iris.Context) {
		ctx.ViewData("", providerIndex)

		if err := ctx.View("index.html"); err != nil {
			ctx.Writef("%v", err)
		}
	})

	app.Run(iris.Addr("localhost:3000"))
}

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}
