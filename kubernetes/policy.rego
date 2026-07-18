# Sample Kubernetes admission-control policies.
# Works against a raw Pod manifest or an AdmissionReview request
# (input.request.object), as used by Gatekeeper/conftest.
package kubernetes.security

import rego.v1

pod_spec := input.request.object.spec if input.request.object.spec

else := input.spec if input.spec

# --- 1. Containers must not run in privileged mode ---

deny contains msg if {
	some container in pod_spec.containers
	container.securityContext.privileged == true
	msg := sprintf("Container '%s' must not run in privileged mode", [container.name])
}

# --- 2. Containers must not run as root ---

deny contains msg if {
	some container in pod_spec.containers
	not container.securityContext.runAsNonRoot == true
	not pod_spec.securityContext.runAsNonRoot == true
	msg := sprintf("Container '%s' must set securityContext.runAsNonRoot = true", [container.name])
}

# --- 3. Containers must declare CPU/memory limits ---

deny contains msg if {
	some container in pod_spec.containers
	not container.resources.limits.cpu
	msg := sprintf("Container '%s' must declare a CPU resource limit", [container.name])
}

deny contains msg if {
	some container in pod_spec.containers
	not container.resources.limits.memory
	msg := sprintf("Container '%s' must declare a memory resource limit", [container.name])
}

# --- 4. Pods must not share the host network or PID namespace ---

deny contains msg if {
	pod_spec.hostNetwork == true
	msg := "Pod must not use hostNetwork: true"
}

deny contains msg if {
	pod_spec.hostPID == true
	msg := "Pod must not use hostPID: true"
}
