# Sample GCP security policies evaluated against Terraform plan JSON
# (terraform show -json plan.tfplan) or raw resource-config JSON.
package gcp.security

import rego.v1

# --- 1. Storage buckets must not be world-readable ---

public_members := {"allUsers", "allAuthenticatedUsers"}

deny contains msg if {
	some resource in input.resources
	resource.type == "google_storage_bucket_iam_binding"
	some member in resource.values.members
	member in public_members
	msg := sprintf("Storage bucket IAM binding '%s' grants access to '%s'", [resource.name, member])
}

# --- 2. Firewall rules must not open sensitive ports to the internet ---

sensitive_ports := {"22", "3389"}

deny contains msg if {
	some resource in input.resources
	resource.type == "google_compute_firewall"
	resource.values.direction == "INGRESS"
	resource.values.source_ranges[_] == "0.0.0.0/0"
	some allowed in resource.values.allow
	some port in allowed.ports
	port in sensitive_ports
	msg := sprintf("Firewall rule '%s' opens port %s to 0.0.0.0/0", [resource.name, port])
}

# --- 3. IAM bindings must not use primitive (basic) roles ---

primitive_roles := {"roles/owner", "roles/editor"}

deny contains msg if {
	some resource in input.resources
	resource.type == "google_project_iam_binding"
	resource.values.role in primitive_roles
	msg := sprintf("IAM binding '%s' uses primitive role '%s'; use a granular role instead", [resource.name, resource.values.role])
}
