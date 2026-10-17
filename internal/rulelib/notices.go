package rulelib

import _ "embed"

//go:embed THIRD_PARTY_NOTICES.md
var thirdPartyNotices string

func ThirdPartyNotices() string { return thirdPartyNotices }
