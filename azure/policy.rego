# Sample Azure security policies evaluated against Terraform plan JSON
# (terraform show -json plan.tfplan) or raw resource-config JSON.
package azure.security

import rego.v1

# --- 1. Storage accounts must not allow public blob access ---

deny contains msg if {
	some resource in input.resources
	resource.type == "azurerm_storage_account"
	resource.values.allow_nested_items_to_be_public == true
	msg := sprintf("Storage account '%s' must not allow public blob access", [resource.name])
}

# --- 2. Network security groups must not expose RDP/SSH to the internet ---

sensitive_ports := {"22", "3389"}

deny contains msg if {
	some resource in input.resources
	resource.type == "azurerm_network_security_rule"
	resource.values.direction == "Inbound"
	resource.values.access == "Allow"
	resource.values.source_address_prefix in {"*", "Internet", "0.0.0.0/0"}
	resource.values.destination_port_range in sensitive_ports
	msg := sprintf(
		"NSG rule '%s' allows inbound port %s from the internet",
		[resource.name, resource.values.destination_port_range],
	)
}

# --- 3. Key Vaults must have purge protection enabled ---

deny contains msg if {
	some resource in input.resources
	resource.type == "azurerm_key_vault"
	resource.values.purge_protection_enabled != true
	msg := sprintf("Key Vault '%s' must enable purge_protection_enabled", [resource.name])
}
