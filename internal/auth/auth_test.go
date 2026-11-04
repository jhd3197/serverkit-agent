package auth

import (
	"sync"
	"testing"
)

func TestConcurrentCredentialUpdates(t *testing.T) {
	a := New("agent", "key-0123456789abcdef", "secret")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				a.UpdateCredentials("key-0123456789abcdef", "secret2")
				a.SetPermissionLevel("protect")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = a.SignMessage(1)
				_ = a.GetAPIKeyPrefix()
				_ = a.PermissionLevel()
			}
		}()
	}
	wg.Wait()
}
