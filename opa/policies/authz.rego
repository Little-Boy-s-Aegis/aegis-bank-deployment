package system.authz

# Get secret token from environment variable passed to OPA
# We can read the AEGIS_SECURITY_SYNC_TOKEN from the environment
import future.keywords.if

default allow := false

# Allow access to policies and data only if token matches expected token
allow if {
    # Extract expected token from environment variable
    expected_token := opa.runtime().env.AEGIS_SECURITY_SYNC_TOKEN
    expected_token != ""
    expected_token != null
    
    # Check if the client provided this token as a Bearer token
    input.identity == expected_token
}
