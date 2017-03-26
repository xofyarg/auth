package main

import (
	"io/ioutil"
	"sync"
	"time"

	yaml "gopkg.in/yaml.v2"
)

const (
	SessionName = "pa"
)

type SessionStore interface {
	Get(user, sid string) (interface{}, bool)
	GetAll(user string) map[string]interface{}
	Add(user, id string, data interface{})
	Remove(user, id string)
	Clear(user string)
	Load(path string) error
	Save(path string) error
}

type StupidStore struct {
	sync.Mutex
	store map[string]map[string]interface{}
}

type StupidData struct {
	UserAgent  string
	CreateTime time.Time
	TTL        time.Duration
}

func NewStupidStore() *StupidStore {
	return &StupidStore{
		store: make(map[string]map[string]interface{}),
	}
}

func (ss *StupidStore) Get(user, id string) (interface{}, bool) {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok || sessions == nil {
		return nil, false
	}

	data, ok := sessions[id]
	if !ok {
		return nil, false
	}

	return data, true
}

func (ss *StupidStore) GetAll(user string) map[string]interface{} {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok || sessions == nil {
		return nil
	}

	sessionsCopy := make(map[string]interface{})
	for k, v := range sessions {
		sessions[k] = v
	}
	return sessionsCopy
}

func (ss *StupidStore) Add(user, id string, data interface{}) {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok {
		sessions = make(map[string]interface{})
		ss.store[user] = sessions
	}
	sessions[id] = data
}

func (ss *StupidStore) Remove(user, id string) {
	ss.Lock()
	defer ss.Unlock()

	sessions, ok := ss.store[user]
	if !ok {
		return
	}
	delete(sessions, id)
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

	var store map[string]map[string]interface{}
	err = yaml.Unmarshal(data, &store)
	if err != nil {
		return err
	}

	ss.Lock()
	defer ss.Unlock()

	ss.store = store
	return nil
}

func (ss *StupidStore) Save(path string) error {
	ss.Lock()
	defer ss.Unlock()

	data, err := yaml.Marshal(ss.store)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(path, data, 0600)
}