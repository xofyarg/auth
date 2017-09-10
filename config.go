package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"regexp"
	"strings"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"
)

const (
	RePrefix = "re:"
	Salt     = "RePPeP"
)

type RuleAction int

const (
	ActionNoMatch RuleAction = -1
	ActionDeny    RuleAction = 0
	ActionAllow   RuleAction = 1
)

type AuthConfig struct {
	Log         string
	Addr        string
	Prefix      string
	PassSalt    string
	SessionSalt string

	Cookie struct {
		Name    string
		TTL     time.Duration
		HashKey string
		Secure  bool
		Domain  string
		Path    string
	}

	Proxy struct {
		Host string
		URI  string
	}

	StoragePath string

	RawUsers []User           `yaml:"users"`
	Users    map[string]*User `yaml:"-"`

	sync.Mutex
}

type User struct {
	Name  string
	Pass  string
	Rules []Rule
}

type Rule struct {
	RawHost   string `yaml:"host"`
	RawUri    string `yaml:"uri"`
	RawAction string `yaml:"action"`

	hostPat *Pattern
	uriPat  *Pattern
	action  RuleAction
}

func ReadConfig(path string) (*AuthConfig, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var conf *AuthConfig
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		return nil, err
	}

	if conf.Cookie.Path == "" {
		conf.Cookie.Path = "/"
	}

	conf.Users = make(map[string]*User)
	for i := range conf.RawUsers {
		user := &conf.RawUsers[i]
		conf.Users[user.Name] = user
		for j := range user.Rules {
			rule := &user.Rules[j]
			rule.hostPat = NewPattern(rule.RawHost)
			rule.uriPat = NewPattern(rule.RawUri)
			switch rule.RawAction {
			case "allow":
				rule.action = ActionAllow
			case "deny":
				rule.action = ActionDeny
			default:
				rule.action = ActionDeny
			}
		}
	}
	return conf, nil
}

func (user *User) MatchRule(host, uri string) RuleAction {
	for i := range user.Rules {
		rule := user.Rules[i]
		if rule.hostPat.Match(host) ||
			rule.uriPat.Match(uri) {
			return rule.action
		}
	}
	return ActionNoMatch
}

func (user *User) VerifyPass(pass, salt string) bool {
	data := sha256.Sum256([]byte(pass + salt))
	return hex.EncodeToString(data[:]) == user.Pass
}

type Pattern struct {
	s  string
	re *regexp.Regexp
}

func NewPattern(s string) *Pattern {
	p := &Pattern{}
	if len(s) == 0 || !strings.HasPrefix(s, RePrefix) {
		p.s = s
	} else {
		p.re = regexp.MustCompile(strings.TrimLeft(s, RePrefix))
	}
	return p
}

func (pat *Pattern) Match(s string) bool {
	if pat.re == nil {
		if len(pat.s) == 0 {
			return true
		} else {
			return pat.s == s
		}
	} else {
		return pat.re.MatchString(s)
	}
}
