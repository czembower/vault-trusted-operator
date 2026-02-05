package authmanager

import (
	"strings"
	"sync/atomic"
)

type credSnapshot struct {
	roleID               string
	inMemSecretID        string
	wrappedSecretIDToken string
}

type CredStore struct {
	creds atomic.Value // *credSnapshot
}

func (c *CredStore) SetRoleID(v string) {
	v = strings.TrimSpace(v)
	c.updateCreds(func(s *credSnapshot) {
		s.roleID = v
	})
}

func (c *CredStore) RoleID() string {
	return c.getSnapshot().roleID
}

func (c *CredStore) SetInMemSecretID(v string) {
	v = strings.TrimSpace(v)
	c.updateCreds(func(s *credSnapshot) {
		s.inMemSecretID = v
	})
}

func (c *CredStore) InMemSecretID() string {
	return c.getSnapshot().inMemSecretID
}

func (c *CredStore) SetWrappedSecretIDToken(v string) {
	v = strings.TrimSpace(v)
	c.updateCreds(func(s *credSnapshot) {
		s.wrappedSecretIDToken = v
	})
}

func (c *CredStore) WrappedSecretIDToken() string {
	return c.getSnapshot().wrappedSecretIDToken
}

// getSnapshot returns the current credential snapshot, creating an empty one if needed.
func (c *CredStore) getSnapshot() *credSnapshot {
	v := c.creds.Load()
	if v == nil {
		return &credSnapshot{}
	}
	return v.(*credSnapshot)
}

// updateCreds atomically updates credentials using a copy-on-write pattern.
func (c *CredStore) updateCreds(fn func(*credSnapshot)) {
	old := c.getSnapshot()
	// Create a shallow copy
	new := &credSnapshot{
		roleID:               old.roleID,
		inMemSecretID:        old.inMemSecretID,
		wrappedSecretIDToken: old.wrappedSecretIDToken,
	}
	fn(new)
	c.creds.Store(new)
}
