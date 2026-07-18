package databricks.security

import rego.v1

good_cluster := {
	"autotermination_minutes": 30,
	"node_type_id": "i3.xlarge",
	"custom_tags": {"environment": "prod", "team": "platform"},
	"data_security_mode": "USER_ISOLATION",
}

test_deny_no_autotermination if {
	values := object.union(good_cluster, {"autotermination_minutes": 0})
	count(deny) > 0 with input as {"resources": [{"type": "databricks_cluster", "name": "etl", "values": values}]}
}

test_deny_disallowed_node_type if {
	values := object.union(good_cluster, {"node_type_id": "r5.24xlarge"})
	count(deny) > 0 with input as {"resources": [{"type": "databricks_cluster", "name": "etl", "values": values}]}
}

test_deny_missing_required_tag if {
	# object.union deep-merges nested objects, so overriding custom_tags there
	# would keep "team" from good_cluster - build the full value instead.
	values := {
		"autotermination_minutes": 30,
		"node_type_id": "i3.xlarge",
		"custom_tags": {"environment": "prod"},
		"data_security_mode": "USER_ISOLATION",
	}
	count(deny) > 0 with input as {"resources": [{"type": "databricks_cluster", "name": "etl", "values": values}]}
}

test_deny_no_data_isolation if {
	values := object.union(good_cluster, {"data_security_mode": "NONE"})
	count(deny) > 0 with input as {"resources": [{"type": "databricks_cluster", "name": "etl", "values": values}]}
}

test_allow_compliant_cluster if {
	count(deny) == 0 with input as {"resources": [{"type": "databricks_cluster", "name": "etl", "values": good_cluster}]}
}
