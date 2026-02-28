package aiauth

import (
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// AnthropicClient returns an authenticated *anthropic.Client.
func (s *Store) AnthropicClient() (*anthropic.Client, error) {
	key, err := s.ResolveKey("anthropic")
	if err != nil {
		return nil, err
	}

	// OAuth tokens (sk-ant-oat01-*) need Bearer auth, not x-api-key
	if strings.HasPrefix(key, "sk-ant-oat01-") {
		c := anthropic.NewClient(
			option.WithHeader("Authorization", "Bearer "+key),
		)
		return &c, nil
	}

	c := anthropic.NewClient(option.WithAPIKey(key))
	return &c, nil
}
