package aiauth

import (
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// AnthropicClient returns an authenticated *anthropic.Client.
// OAuth tokens (sk-ant-oat01-*) and API keys (sk-ant-api03-*) both use x-api-key header.
func (s *Store) AnthropicClient() (*anthropic.Client, error) {
	key, err := s.ResolveKey("anthropic")
	if err != nil {
		return nil, err
	}

	c := anthropic.NewClient(option.WithAPIKey(key))
	return &c, nil
}
