package internal

import (
	"fmt"
	"log/slog"
	"strconv"
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

	dynamicCount := int64(0)
	allowed := int64(0)
	denied := int64(0)
	grantors := ""
	if m.policy != nil {
		dynamicCount = int64(m.policy.DynamicCount())
		grantors = strings.Join(m.policy.Grantors(), ",")
	}
	if m.srv != nil {
		allowed = m.srv.AllowedCount()
		denied = m.srv.DeniedCount()
	}

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
		{
			Key:         "policy_dev_file",
			Label:       "Dev Policy Overlay",
			Type:        contracts.SettingTypeString,
			Value:       m.overlayPath,
			Description: "Optional dev overlay YAML (CALL_POLICY_DEV_FILE); appended on load/reload",
			Group:       "Policy",
		},
		{
			Key:         "grantors",
			Label:       "Dynamic Grant Grantors",
			Type:        contracts.SettingTypeString,
			Value:       grantors,
			Description: "Comma-separated module IDs allowed to publish call.policy.grant/revoke (also grantors: in YAML)",
			Group:       "Policy",
		},
		{
			Key:         "dynamic_grants",
			Label:       "Active Dynamic Grants",
			Type:        contracts.SettingTypeInt,
			Value:       strconv.FormatInt(dynamicCount, 10),
			Description: "Runtime grants from call.policy.grant (read-only)",
			Group:       "Metrics",
		},
		{
			Key:         "calls_allowed",
			Label:       "Calls Allowed",
			Type:        contracts.SettingTypeInt,
			Value:       strconv.FormatInt(allowed, 10),
			Description: "Total AllowCall decisions that allowed (read-only)",
			Group:       "Metrics",
		},
		{
			Key:         "calls_denied",
			Label:       "Calls Denied",
			Type:        contracts.SettingTypeInt,
			Value:       strconv.FormatInt(denied, 10),
			Description: "Total AllowCall decisions that denied (read-only)",
			Group:       "Metrics",
		},
		{
			Key:         "policy_reload",
			Label:       "Reload Policy",
			Type:        contracts.SettingTypeBool,
			Value:       "false",
			Description: "Set to true to reload policy_file + overlay from disk without changing paths",
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
	case "policy_dev_file", "CALL_POLICY_DEV_FILE":
		m.cfgMu.Lock()
		m.overlayPath = value
		m.cfgMu.Unlock()
		if m.policy == nil {
			return nil
		}
		return m.ReloadPolicy()
	case "grantors":
		if m.policy == nil {
			return nil
		}
		var grantors []string
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				grantors = append(grantors, part)
			}
		}
		m.policy.SetGrantors(grantors)
		return nil
	case "policy_reload":
		if strings.EqualFold(value, "true") || value == "1" {
			if m.policy == nil {
				return nil
			}
			return m.ReloadPolicy()
		}
		return nil
	case "dynamic_grants", "calls_allowed", "calls_denied":
		return fmt.Errorf("setting %q is read-only", key)
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

// ReloadPolicy reloads the YAML policy file and replaces static rules.
func (m *Module) ReloadPolicy() error {
	m.cfgMu.RLock()
	path := m.filePath
	overlay := m.overlayPath
	m.cfgMu.RUnlock()
	newP, err := policy.LoadWithOverlay(path, overlay)
	if err != nil {
		return err
	}
	m.policy.ReplaceRules(newP)
	slog.Info("call-policy reloaded", "file", path, "overlay", overlay)
	return nil
}
