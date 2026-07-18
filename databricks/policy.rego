# Sample Databricks security policies evaluated against Terraform plan JSON
# (terraform show -json plan.tfplan) for the databricks provider.
package databricks.security

import rego.v1

# --- 1. Clusters must auto-terminate to limit cost and attack surface ---

deny contains msg if {
	some resource in input.resources
	resource.type == "databricks_cluster"
	autotermination := object.get(resource.values, "autotermination_minutes", 0)
	autotermination == 0
	msg := sprintf("Cluster '%s' must set autotermination_minutes > 0", [resource.name])
}

# --- 2. Clusters must only use approved node types ---

allowed_node_types := {"i3.xlarge", "i3.2xlarge", "m5.xlarge"}

deny contains msg if {
	some resource in input.resources
	resource.type == "databricks_cluster"
	not resource.values.node_type_id in allowed_node_types
	msg := sprintf(
		"Cluster '%s' uses disallowed node type '%s'",
		[resource.name, resource.values.node_type_id],
	)
}

# --- 3. Clusters must be tagged for cost/ownership tracking ---

required_tags := {"environment", "team"}

deny contains msg if {
	some resource in input.resources
	resource.type == "databricks_cluster"
	some tag in required_tags
	not resource.values.custom_tags[tag]
	msg := sprintf("Cluster '%s' is missing required tag '%s'", [resource.name, tag])
}

# --- 4. Clusters accessing Unity Catalog data must enforce data isolation ---

deny contains msg if {
	some resource in input.resources
	resource.type == "databricks_cluster"
	resource.values.data_security_mode == "NONE"
	msg := sprintf("Cluster '%s' must not use data_security_mode = NONE; use USER_ISOLATION or SINGLE_USER", [resource.name])
}
