package internal

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/Muxcore-Media/call-policy-default/internal/policy"
	"github.com/Muxcore-Media/core/pkg/contracts"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	return []contracts.SettingDef{
		{
			Key:         "policy_file",
			Label:       "Call Policy File",
			Type:        contracts.SettingTypeString,
			Value:       m.filePath,
			Default:     "policies.yaml",
			Description: "Path to YAML call policy (CALL_POLICY_FILE); updates reload immediately",
			Group:       "Policy",
		},
	}
}

func (m *Module) updateSetting(key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "policy_file", "CALL_POLICY_FILE":
		if value == "" {
			return fmt.Errorf("policy_file must not be empty")
		}
		m.cfgMu.Lock()
		m.filePath = value
		m.cfgMu.Unlock()
		if m.policy == nil {
			return nil
		}
		return m.ReloadPolicy()
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

// ReloadPolicy reloads the YAML policy file and replaces static rules.
func (m *Module) ReloadPolicy() error {
	m.cfgMu.RLock()
	path := m.filePath
	m.cfgMu.RUnlock()
	overlay := strings.TrimSpace(os.Getenv("CALL_POLICY_DEV_FILE"))
	newP, err := policy.LoadWithOverlay(path, overlay)
	if err != nil {
		return err
	}
	m.policy.ReplaceRules(newP)
	slog.Info("call-policy reloaded", "file", path, "overlay", overlay)
	return nil
}
