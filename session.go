package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	yaml "gopkg.in/yaml.v2"
)

const (
	HashPrefixLen = 8 // only show part of the hash
)

type Session struct {
	UserAgent  string
	CreateTime time.Time
	TTL        time.Duration
}

type SessionStore interface {
	Get(user, sid string) (*Session, bool)
	GetAll(user string) map[string]*Session
	Add(user, id string, s *Session)
	Remove(user, id string)
	RemoveHash(user, id string)
	Clear(user string)
	Load(path string) error
	Save(path string) error
}

type StupidStore struct {
	salt string
	sync.Mutex
	store map[string]map[string]*Session
}

func NewStupidStore(salt string) *StupidStore {
	return &StupidStore{
		store: make(map[string]map[string]*Session),
		salt:  salt,
	}
}

func (ss *StupidStore) hash(id string) string {
	h := sha256.Sum256([]byte(id + ss.salt))
	return hex.EncodeToString(h[:])
}

func (ss *StupidStore) Get(user, id string) (*Session, bool) {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok || sessions == nil {
		return nil, false
	}

	data, ok := sessions[ss.hash(id)]
	if !ok {
		return nil, false
	}

	return data, true
}

func (ss *StupidStore) GetAll(user string) map[string]*Session {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok || sessions == nil {
		return nil
	}

	sessionsCopy := make(map[string]*Session)
	for k, v := range sessions {
		sessionsCopy[k[:HashPrefixLen]] = v
	}
	return sessionsCopy
}

func (ss *StupidStore) Add(user, id string, s *Session) {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok {
		sessions = make(map[string]*Session)
		ss.store[user] = sessions
	}

	sessions[ss.hash(id)] = s
}

func (ss *StupidStore) Remove(user, id string) {
	ss.RemoveHash(user, ss.hash(id))
}

func (ss *StupidStore) RemoveHash(user, id string) {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok {
		return
	}

	if len(id) > HashPrefixLen {
		delete(sessions, id)
	} else {
		var full string
		for k, _ := range sessions {
			if strings.HasPrefix(k, id) {
				full = k
				break
			}
		}
		delete(sessions, full)
	}
}

func (ss *StupidStore) Clear(user string) {
	ss.Lock()
	defer ss.Unlock()

	delete(ss.store, user)
}

func (ss *StupidStore) Load(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	var store map[string]map[string]*Session
	err = yaml.Unmarshal(data, &store)
	if err != nil {
		return err
	}

	ss.Lock()
	defer ss.Unlock()

	ss.store = store
	ss.expire()

	return nil
}

func (ss *StupidStore) expire() {
	toRemove := make(map[string][]string)

	now := time.Now().UTC()

	for user, sessions := range ss.store {
		for id, s := range sessions {
			if s.CreateTime.Add(s.TTL).Before(now) {
				toRemove[user] = append(toRemove[user], id)
			}
		}
	}

	for user, sessions := range ss.store {
		ids, ok := toRemove[user]
		if !ok {
			continue
		}
		for _, id := range ids {
			zap.L().Info("expired session removed",
				zap.String("user", user), zap.String("id", id[:HashPrefixLen]))
			delete(sessions, id)
		}
	}
}

func (ss *StupidStore) Save(path string) error {
	ss.Lock()
	defer ss.Unlock()

	ss.expire()

	data, err := yaml.Marshal(ss.store)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, 0600)
}
