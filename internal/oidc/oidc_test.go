package oidc

import (
	"errors"
	"fmt"
	"testing"
)

// fakeAgentErr mimics liboidcagent's OIDCAgentError: it carries a help message
// exposed via ErrorWithHelp, satisfying AgentHelper.
type fakeAgentErr struct{}

func (fakeAgentErr) Error() string { return "oidc-agent error: account not loaded" }
func (fakeAgentErr) ErrorWithHelp() string {
	return "oidc-agent error: account not loaded\nRun 'oidc-add <account>'."
}

func TestAgentErrorMessage(t *testing.T) {
	helpMsg := "oidc-agent error: account not loaded\nRun 'oidc-add <account>'."

	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "agent error surfaces its help text",
			err:  fakeAgentErr{},
			want: helpMsg,
		},
		{
			name: "agent error is unwrapped from a wrapping error",
			err:  fmt.Errorf("getting token: %w", fakeAgentErr{}),
			want: helpMsg,
		},
		{
			name: "plain error falls back to its message",
			err:  errors.New("something else"),
			want: "something else",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := AgentErrorMessage(tc.err); got != tc.want {
				t.Errorf("AgentErrorMessage() = %q, want %q", got, tc.want)
			}
		})
	}
}
