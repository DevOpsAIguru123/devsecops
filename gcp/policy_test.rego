package gcp.security

import rego.v1

test_deny_public_bucket_binding if {
	count(deny) > 0 with input as {"resources": [{
		"type": "google_storage_bucket_iam_binding",
		"name": "assets",
		"values": {"members": ["allUsers"]},
	}]}
}

test_allow_private_bucket_binding if {
	count(deny) == 0 with input as {"resources": [{
		"type": "google_storage_bucket_iam_binding",
		"name": "assets",
		"values": {"members": ["group:data-team@example.com"]},
	}]}
}

test_deny_open_firewall_rule if {
	count(deny) > 0 with input as {"resources": [{
		"type": "google_compute_firewall",
		"name": "allow-ssh",
		"values": {
			"direction": "INGRESS",
			"source_ranges": ["0.0.0.0/0"],
			"allow": [{"ports": ["22"]}],
		},
	}]}
}

test_allow_restricted_firewall_rule if {
	count(deny) == 0 with input as {"resources": [{
		"type": "google_compute_firewall",
		"name": "allow-ssh",
		"values": {
			"direction": "INGRESS",
			"source_ranges": ["10.0.0.0/16"],
			"allow": [{"ports": ["22"]}],
		},
	}]}
}

test_deny_primitive_role_binding if {
	count(deny) > 0 with input as {"resources": [{
		"type": "google_project_iam_binding",
		"name": "editors",
		"values": {"role": "roles/editor"},
	}]}
}
