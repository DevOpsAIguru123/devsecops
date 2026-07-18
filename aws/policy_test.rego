package aws.security

import rego.v1

test_deny_public_s3_acl if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_s3_bucket",
		"name": "logs",
		"values": {"acl": "public-read"},
	}]}
}

test_allow_private_s3_acl if {
	count(deny) == 0 with input as {"resources": [{
		"type": "aws_s3_bucket",
		"name": "logs",
		"values": {"acl": "private"},
	}]}
}

test_deny_open_ssh_security_group if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_security_group",
		"name": "default",
		"values": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22}]},
	}]}
}

test_allow_restricted_security_group if {
	count(deny) == 0 with input as {"resources": [{
		"type": "aws_security_group",
		"name": "default",
		"values": {"ingress": [{"cidr_blocks": ["10.0.0.0/16"], "from_port": 22}]},
	}]}
}

test_deny_wildcard_iam_policy if {
	count(deny) > 0 with input as {"resources": [{
		"type": "aws_iam_policy",
		"name": "admin",
		"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"},
	}]}
}
