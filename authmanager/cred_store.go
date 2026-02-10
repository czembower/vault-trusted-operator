package authmanager

import (
	"strings"
	"sync"
	"time"
)

type CredStore struct {
	mu                      sync.Mutex
	roleID                  string
	inMemSecretID           string
	inMemSecretIDObtainedAt time.Time // When the current in-memory secret ID was obtained
	inMemSecretIDConsumed   bool      // Whether it's been used for login (single-use)
	wrappedSecretIDToken    string
	wrappedObtainedAt       time.Time // When the current wrapped token was obtained
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
	if v != "" {
		c.inMemSecretIDObtainedAt = time.Now()
		c.inMemSecretIDConsumed = false
	} else {
		c.inMemSecretIDObtainedAt = time.Time{}
		c.inMemSecretIDConsumed = false
	}
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
	if v != "" {
		c.wrappedObtainedAt = time.Now()
	} else {
		c.wrappedObtainedAt = time.Time{}
	}
	c.mu.Unlock()
}

func (c *CredStore) WrappedSecretIDToken() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wrappedSecretIDToken
}

// MarkInMemSecretIDConsumed marks the in-memory secret ID as consumed (used for login).
// Since secret IDs are single-use, this indicates the credential is no longer valid.
func (c *CredStore) MarkInMemSecretIDConsumed() {
	c.mu.Lock()
	c.inMemSecretIDConsumed = true
	c.mu.Unlock()
}

// InMemSecretIDAge returns the age of the current in-memory secret ID.
// Returns 0 if no secret ID is present.
func (c *CredStore) InMemSecretIDAge() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inMemSecretIDObtainedAt.IsZero() {
		return 0
	}
	return time.Since(c.inMemSecretIDObtainedAt)
}

// IsInMemSecretIDConsumed returns true if the in-memory secret ID has been marked as consumed.
func (c *CredStore) IsInMemSecretIDConsumed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inMemSecretIDConsumed
}

// WrappedSecretIDAge returns the age of the current wrapped secret ID token.
// Returns 0 if no wrapped token is present.
func (c *CredStore) WrappedSecretIDAge() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.wrappedObtainedAt.IsZero() {
		return 0
	}
	return time.Since(c.wrappedObtainedAt)
}
