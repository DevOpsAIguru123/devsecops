package kubernetes.security

import rego.v1

good_container := {
	"name": "app",
	"securityContext": {"privileged": false, "runAsNonRoot": true},
	"resources": {"limits": {"cpu": "500m", "memory": "256Mi"}},
}

test_deny_privileged_container if {
	container := object.union(good_container, {"securityContext": {"privileged": true}})
	count(deny) > 0 with input as {"spec": {"containers": [container]}}
}

test_deny_missing_run_as_non_root if {
	container := object.remove(good_container, ["securityContext"])
	count(deny) > 0 with input as {"spec": {"containers": [container]}}
}

test_deny_missing_resource_limits if {
	container := object.remove(good_container, ["resources"])
	count(deny) > 0 with input as {"spec": {"containers": [container]}}
}

test_deny_host_network if {
	count(deny) > 0 with input as {"spec": {"hostNetwork": true, "containers": [good_container]}}
}

test_allow_compliant_pod if {
	count(deny) == 0 with input as {"spec": {"containers": [good_container]}}
}

test_allow_compliant_admission_review if {
	count(deny) == 0 with input as {"request": {"object": {"spec": {"containers": [good_container]}}}}
}
