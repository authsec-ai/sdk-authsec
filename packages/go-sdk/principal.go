package authsec

type Principal struct {
	Subject  string
	Issuer   string
	Audience []string
	Scopes   []string
	Claims   map[string]any
	Active   bool
}

func (p *Principal) HasAnyScope(required []string) bool {
	if len(required) == 0 {
		return true
	}
	granted := make(map[string]struct{}, len(p.Scopes))
	for _, scope := range p.Scopes {
		granted[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := granted[scope]; ok {
			return true
		}
	}
	return false
}
