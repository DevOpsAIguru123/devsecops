package azure.security

import rego.v1

test_deny_public_blob_access if {
	count(deny) > 0 with input as {"resources": [{
		"type": "azurerm_storage_account",
		"name": "sademo",
		"values": {"allow_nested_items_to_be_public": true},
	}]}
}

test_allow_private_blob_access if {
	count(deny) == 0 with input as {"resources": [{
		"type": "azurerm_storage_account",
		"name": "sademo",
		"values": {"allow_nested_items_to_be_public": false},
	}]}
}

test_deny_open_rdp_rule if {
	count(deny) > 0 with input as {"resources": [{
		"type": "azurerm_network_security_rule",
		"name": "allow-rdp",
		"values": {
			"direction": "Inbound",
			"access": "Allow",
			"source_address_prefix": "Internet",
			"destination_port_range": "3389",
		},
	}]}
}

test_allow_restricted_rdp_rule if {
	count(deny) == 0 with input as {"resources": [{
		"type": "azurerm_network_security_rule",
		"name": "allow-rdp",
		"values": {
			"direction": "Inbound",
			"access": "Allow",
			"source_address_prefix": "10.0.0.0/16",
			"destination_port_range": "3389",
		},
	}]}
}

test_deny_keyvault_without_purge_protection if {
	count(deny) > 0 with input as {"resources": [{
		"type": "azurerm_key_vault",
		"name": "kvdemo",
		"values": {"purge_protection_enabled": false},
	}]}
}
