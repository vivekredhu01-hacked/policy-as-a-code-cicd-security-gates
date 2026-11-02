package main

import data.securitygate
import rego.v1

deny contains message if {
	securitygate.decision == "BLOCK"
	message := json.marshal(securitygate.decision_record)
}

warn contains message if {
	securitygate.decision == "WARN"
	message := json.marshal(securitygate.decision_record)
}
