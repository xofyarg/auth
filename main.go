package main

import (
	"flag"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"

	"go.uber.org/zap"
)

type Auth struct {
	cookieStore    *sessions.CookieStore
	activeSessions SessionStore

	conf *AuthConfig
}

func (a *Auth) Status(w http.ResponseWriter, r *http.Request) {
	a.conf.Lock()
	conf := a.conf
	a.conf.Unlock()

	session, err := a.cookieStore.Get(r, conf.Cookie.Name)
	if err != nil {
		http.Error(w, "", http.StatusInternalServerError)
		zap.L().Error("cannot create session", zap.Error(err))
		return
	}

	if session.IsNew {
		TemplateLogin.Execute(w, nil)
		return
	}

	cookie, err := r.Cookie(conf.Cookie.Name)
	if err != nil {
		TemplateLogin.Execute(w, nil)
		return
	}

	username := session.Values["user"].(string)
	current, ok := a.activeSessions.Get(username, cookie.Value)
	if !ok {
		TemplateLogin.Execute(w, nil)
		return
	}

	if data := a.activeSessions.GetAll(username); data != nil {
		var cur string
		for id, session := range data {
			if current.UserAgent == session.UserAgent &&
				current.CreateTime == session.CreateTime {
				cur = id
				break
			}
		}

		err := TemplateStatus.Execute(w,
			struct {
				Current  string
				Sessions map[string]*Session
			}{cur, data})
		if err != nil {
			zap.L().Error("status template", zap.Error(err))
		}
		return
	}

	zap.L().Debug("no matching active session")
	session.Options.MaxAge = -1
	session.Save(r, w)
	TemplateLogin.Execute(w, nil)
}

func (a *Auth) Action(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")
	switch action {
	case "login":
		a.Login(w, r)
	case "logout":
		a.Logout(w, r)
	default:
		http.Error(w, "invalid argument", http.StatusBadRequest)
	}
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	a.conf.Lock()
	conf := a.conf
	a.conf.Unlock()

	user, ok := conf.Users[username]
	if !ok {
		http.Error(w, "wrong username/password", http.StatusForbidden)
		return
	}
	if !user.VerifyPass(password, conf.PassSalt) {
		http.Error(w, "wrong username/password", http.StatusForbidden)
		return
	}

	session, err := a.cookieStore.Get(r, conf.Cookie.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["user"] = username
	session.Save(r, w)

	// get cookie value as session id
	sid := strings.TrimLeft(
		strings.Split(
			w.Header().Get("Set-Cookie"),
			"; ",
		)[0],
		conf.Cookie.Name+"=",
	)

	a.activeSessions.Add(username, sid, &Session{
		UserAgent:  r.UserAgent(),
		CreateTime: time.Now().UTC(),
		TTL:        conf.Cookie.TTL,
	})
	http.Error(w, "logged in", http.StatusOK)
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	a.conf.Lock()
	conf := a.conf
	a.conf.Unlock()

	session, err := a.cookieStore.Get(r, conf.Cookie.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if session.IsNew {
		return
	}

	username := session.Values["user"].(string)

	sid := r.FormValue("remove")
	if sid != "" {
		a.activeSessions.RemoveHash(username, sid)
	} else {
		cookie, _ := r.Cookie(conf.Cookie.Name)
		a.activeSessions.Remove(username, cookie.Value)
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Error(w, "logged out", http.StatusOK)
	}
}

func (a *Auth) Verify(w http.ResponseWriter, r *http.Request) {
	a.conf.Lock()
	conf := a.conf
	a.conf.Unlock()

	session, err := a.cookieStore.Get(r, conf.Cookie.Name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if session.IsNew {
		zap.L().Debug("no session cookie found")
		http.Error(w, "", http.StatusForbidden)
		return
	}

	username := session.Values["user"].(string)
	cookie, _ := r.Cookie(conf.Cookie.Name)
	if _, ok := a.activeSessions.Get(username, cookie.Value); !ok {
		session.Options.MaxAge = -1
		session.Save(r, w)
		http.Error(w, "", http.StatusForbidden)
		return
	}

	match(w, r, username, conf)
}

func (a *Auth) BasicAuth(w http.ResponseWriter, r *http.Request) {
	a.conf.Lock()
	conf := a.conf
	a.conf.Unlock()

	username, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Please login."`)
		http.Error(w, "", http.StatusUnauthorized)
		return
	}
	user, ok := conf.Users[username]
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Please login."`)
		http.Error(w, "wrong username/password", http.StatusUnauthorized)
		return
	}
	if !user.VerifyPass(password, conf.PassSalt) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Please login."`)
		http.Error(w, "wrong username/password", http.StatusUnauthorized)
		return
	}

	match(w, r, username, conf)
}

func match(w http.ResponseWriter, r *http.Request,
	username string, conf *AuthConfig) {
	user, ok := conf.Users[username]
	if !ok {
		zap.L().Debug("no registered user found",
			zap.String("user", username))
		http.Error(w, "", http.StatusForbidden)
		return
	}

	host := r.Header.Get(conf.Proxy.Host)
	uri := r.Header.Get(conf.Proxy.URI)

	zap.L().Debug("matching rules",
		zap.String("user", username),
		zap.String("host", host),
		zap.String("uri", uri))

	action := user.MatchRule(host, uri)
	switch action {
	case ActionNoMatch, ActionDeny:
		http.Error(w, "", http.StatusForbidden)
	case ActionAllow:
		w.Header().Set("X-User", username)
		http.Error(w, "", http.StatusOK)
	}
	zap.L().Debug("rule matching",
		zap.String("user", username),
		zap.Any("action", action))
}

func (a *Auth) Log(w http.ResponseWriter, r *http.Request, status int) {
	a.conf.Lock()
	conf := a.conf
	a.conf.Unlock()

	session, err := a.cookieStore.Get(r, conf.Cookie.Name)
	var user string
	if err == nil && !session.IsNew {
		user = session.Values["user"].(string)
	}

	if user == "" {
		user = w.Header().Get("X-User")
	}

	host := r.Header.Get(conf.Proxy.Host)
	uri := r.Header.Get(conf.Proxy.URI)

	zap.L().Info("",
		//zap.String("remote", r.RemoteAddr),
		zap.String("user-agent", r.UserAgent()),
		zap.String("method", r.Method),
		zap.String("endpoint", r.RequestURI),
		zap.String("host", host),
		zap.String("uri", uri),
		zap.Int("status", status),
		zap.String("user", user),
	)
}

func main() {
	logger, _ := zap.NewProductionConfig().Build()
	zap.ReplaceGlobals(logger)

	confpath := flag.String("conf", "config.yaml", "path to config file")
	flag.Parse()

	var err error
	auth := &Auth{}

	auth.conf, err = ReadConfig(*confpath)
	if err != nil {
		zap.L().Error("cannot load config", zap.Error(err))
		os.Exit(1)
	}

	if auth.conf.Log != "" {
		zcfg := zap.NewProductionConfig()
		err := zcfg.Level.UnmarshalText([]byte(auth.conf.Log))
		if err != nil {
			zap.L().Error("cannot set log level", zap.Error(err))
			os.Exit(1)
		}
		logger, _ := zcfg.Build()
		zap.ReplaceGlobals(logger)
	}

	auth.cookieStore = sessions.NewCookieStore([]byte(auth.conf.Cookie.HashKey))
	auth.cookieStore.Options = &sessions.Options{
		MaxAge:   int(auth.conf.Cookie.TTL.Seconds()),
		Path:     auth.conf.Cookie.Path,
		HttpOnly: true,
		Domain:   auth.conf.Cookie.Domain,
		Secure:   auth.conf.Cookie.Secure,
	}

	auth.activeSessions = NewStupidStore(auth.conf.SessionSalt)
	err = auth.activeSessions.Load(auth.conf.StoragePath)
	if err != nil {
		zap.L().Warn("cannot load session data", zap.Error(err))
	}

	go func() {
		t := time.Tick(30 * time.Second)
		for _ = range t {
			err := auth.activeSessions.Save(auth.conf.StoragePath)
			if err != nil {
				zap.L().Warn("cannot save session data", zap.Error(err))
			}
		}
	}()

	serve(auth)
}

type statusWriter struct {
	status int
	http.ResponseWriter
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func serve(auth *Auth) error {
	prefix := auth.conf.Prefix

	router := mux.NewRouter()
	router.HandleFunc(prefix+"/", auth.Status).Methods("GET")
	router.HandleFunc(prefix+"/", auth.Action).Methods("POST")
	router.HandleFunc(prefix+"/verify/", auth.Verify)
	router.HandleFunc(prefix+"/basic/", auth.BasicAuth)
	//h := handlers.CombinedLoggingHandler(os.Stdout, r)

	logger := func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{http.StatusOK, w}
		router.ServeHTTP(sw, r)
		auth.Log(w, r, sw.status)
	}

	zap.L().Info("starting auth server", zap.String("addr", auth.conf.Addr))
	return http.ListenAndServe(auth.conf.Addr, http.HandlerFunc(logger))
}
