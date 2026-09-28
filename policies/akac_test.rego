package akac

import rego.v1

test_known_company_request if {
    allow with input as {"tenant": "acme", "purpose": "work", "action": "read", "classification": "internal"}
}
test_unknown_company_denied if {
    not allow with input as {"tenant": "other", "purpose": "work", "action": "read", "classification": "public"}
}
test_declassification_denied if {
    not allow with input as {"tenant": "acme", "purpose": "work", "action": "declassify", "classification": "restricted"}
}
test_missing_attributes_denied if {
    not allow with input as {}
}
