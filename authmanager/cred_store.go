package authmanager

import (
	"strings"
	"sync"
)

type CredStore struct {
	mu                   sync.Mutex
	roleID               string
	inMemSecretID        string
	wrappedSecretIDToken string
}

func (c *CredStore) SetRoleID(v string) {
	v = strings.TrimSpace(v)
	c.mu.Lock()
	c.roleID = v
	c.mu.Unlock()
}

func (c *CredStore) RoleID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.roleID
}

func (c *CredStore) SetInMemSecretID(v string) {
	v = strings.TrimSpace(v)
	c.mu.Lock()
	c.inMemSecretID = v
	c.mu.Unlock()
}

func (c *CredStore) InMemSecretID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inMemSecretID
}

func (c *CredStore) SetWrappedSecretIDToken(v string) {
	v = strings.TrimSpace(v)
	c.mu.Lock()
	c.wrappedSecretIDToken = v
	c.mu.Unlock()
}

func (c *CredStore) WrappedSecretIDToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wrappedSecretIDToken
}
