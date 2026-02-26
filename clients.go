package aiauth

import (
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// AnthropicClient returns an authenticated *anthropic.Client.
func (s *Store) AnthropicClient() (*anthropic.Client, error) {
	key, err := s.ResolveKey("anthropic")
	if err != nil {
		return nil, err
	}
	c := anthropic.NewClient(option.WithAPIKey(key))
	return &c, nil
}
