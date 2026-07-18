# Sample AWS security policies evaluated against Terraform plan JSON
# (terraform show -json plan.tfplan) or raw resource-config JSON.
package aws.security

import rego.v1

# --- 1. S3 buckets must not be publicly readable/writable ---

deny contains msg if {
	some resource in input.resources
	resource.type == "aws_s3_bucket"
	resource.values.acl in {"public-read", "public-read-write"}
	msg := sprintf("S3 bucket '%s' must not use a public ACL (found '%s')", [resource.name, resource.values.acl])
}

# --- 2. Security groups must not expose admin ports to the internet ---

sensitive_ports := {22, 3389}

deny contains msg if {
	some resource in input.resources
	resource.type == "aws_security_group"
	some rule in resource.values.ingress
	rule.cidr_blocks[_] == "0.0.0.0/0"
	rule.from_port in sensitive_ports
	msg := sprintf(
		"Security group '%s' allows port %d from 0.0.0.0/0",
		[resource.name, rule.from_port],
	)
}

# --- 3. IAM policies must not grant wildcard actions on all resources ---

deny contains msg if {
	some resource in input.resources
	resource.type == "aws_iam_policy"
	statement := json.unmarshal(resource.values.policy).Statement[_]
	statement.Effect == "Allow"
	statement.Action == "*"
	statement.Resource == "*"
	msg := sprintf("IAM policy '%s' grants '*' action on '*' resource", [resource.name])
}
