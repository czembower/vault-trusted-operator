// cred_store.go
package main

import (
	"errors"
	"os"
	"strings"
	"sync"
)

type CredStore struct {
	mu sync.RWMutex

	roleID               string
	inMemSecretID        string
	wrappedSecretIDToken string
}

func (c *CredStore) SetRoleID(v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roleID = strings.TrimSpace(v)
}

func (c *CredStore) RoleID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.roleID
}

func (c *CredStore) SetInMemSecretID(v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inMemSecretID = strings.TrimSpace(v)
}

func (c *CredStore) InMemSecretID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.inMemSecretID
}

func (c *CredStore) SetWrappedSecretIDToken(v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wrappedSecretIDToken = strings.TrimSpace(v)
}

func (c *CredStore) WrappedSecretIDToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.wrappedSecretIDToken
}

func (c *CredStore) LoadRoleIDFromFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return errors.New("role-id file empty")
	}
	c.SetRoleID(v)
	return nil
}

func (c *CredStore) LoadWrappedSecretIDTokenFromFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return errors.New("secret-id file empty")
	}
	c.SetWrappedSecretIDToken(v)
	return nil
}
