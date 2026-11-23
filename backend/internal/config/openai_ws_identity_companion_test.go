package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOpenAIWSIdentityCompanionRequiresExactPackageAndScope(t *testing.T) {
	resetViperWithJWTSecret(t)
	cfg, err := Load()
	require.NoError(t, err)
	require.False(t, cfg.Plugins.OpenAIWSIdentityCompanionConfigured())
	require.False(t, cfg.Plugins.OpenAIWSIdentityCompanionGlobal)
	cfg.Plugins.OpenAIWSIdentityCompanionPackage = "/tmp/candidate-only/native.s2plugin"
	require.ErrorContains(t, cfg.Validate(), "require an absolute path and its lowercase SHA-256")
	cfg.Plugins.OpenAIWSIdentityCompanionSHA256 = strings.Repeat("a", 64)
	require.ErrorContains(t, cfg.Validate(), "requires an explicit account and API key canary")
	cfg.Plugins.OpenAIWSIdentityCanaryAccountID = 901
	cfg.Plugins.OpenAIWSIdentityCanaryAPIKeyID = 101
	require.NoError(t, cfg.Validate())
	require.False(t, cfg.Plugins.AllowsOpenAIWSIdentity(901, 101), "a configured archive does not enable native WS")
	cfg.Plugins.OpenAIWSIdentityCompanionPackage = "relative/native.s2plugin"
	require.ErrorContains(t, cfg.Validate(), "absolute path")
}

func TestOpenAIWSIdentityCompanionGlobalExplicitOptIn(t *testing.T) {
	resetViperWithJWTSecret(t)
	t.Setenv("PLUGINS_OPENAI_WS_IDENTITY_COMPANION_GLOBAL", "true")
	t.Setenv("PLUGINS_OPENAI_WS_IDENTITY_COMPANION_PACKAGE", "/tmp/native.s2plugin")
	t.Setenv("PLUGINS_OPENAI_WS_IDENTITY_COMPANION_SHA256", strings.Repeat("a", 64))
	t.Setenv("PLUGINS_OPENAI_WS_IDENTITY_ENABLED", "true")
	cfg, err := Load()
	require.NoError(t, err)
	require.True(t, cfg.Plugins.OpenAIWSIdentityCompanionGlobal)
	require.Zero(t, cfg.Plugins.OpenAIWSIdentityCanaryAccountID)
	require.Zero(t, cfg.Plugins.OpenAIWSIdentityCanaryAPIKeyID)
	require.True(t, cfg.Plugins.AllowsOpenAIWSIdentity(901, 101))
	require.True(t, cfg.Plugins.AllowsOpenAIWSIdentity(902, 102))
	require.False(t, cfg.Plugins.AllowsOpenAIWSIdentity(0, 101))
	require.False(t, cfg.Plugins.AllowsOpenAIWSIdentity(901, 0))
	base := cfg.Plugins
	cfg.Plugins.OpenAIWSIdentityEnabled = false
	require.False(t, cfg.Plugins.AllowsOpenAIWSIdentity(901, 101))
	cfg.Plugins = base
	cfg.Plugins.OpenAIWSIdentityCanaryAccountID = 901
	cfg.Plugins.OpenAIWSIdentityCanaryAPIKeyID = 101
	require.ErrorContains(t, cfg.Validate(), "cannot be combined with canary IDs")
	require.False(t, cfg.Plugins.AllowsOpenAIWSIdentity(901, 101))
	cfg.Plugins = base
	cfg.Plugins.OpenAIWSIdentityCompanionGlobal = false
	require.ErrorContains(t, cfg.Validate(), "requires an explicit account and API key canary")
	require.False(t, cfg.Plugins.AllowsOpenAIWSIdentity(901, 101))
	cfg.Plugins = base
	cfg.Plugins.OpenAIWSIdentityCompanionPackage = ""
	cfg.Plugins.OpenAIWSIdentityCompanionSHA256 = ""
	require.ErrorContains(t, cfg.Validate(), "requires a companion package")
	require.False(t, cfg.Plugins.AllowsOpenAIWSIdentity(901, 101))
}
