package main

// displayNames also works for existing reports without rebuilding configuration.
// Native identifiers remain unchanged; these names are presentation metadata.
func displayNames(r Report) map[string]string {
	names := map[string]string{
		"direct": "直连", "block": "拦截", "reject": "拦截",
		"must_direct": "强制直连", "must_block": "强制拦截",
	}
	for _, p := range r.Providers {
		if p.Kind == "rules" {
			names[id("r_", p.Name)] = p.Name
		}
	}
	for _, g := range r.Groups {
		names[g.ID] = g.Name
	}
	for _, n := range r.Nodes {
		names[n.ID] = n.Name
		names[id("solo_", n.Name)] = n.Name
	}
	return names
}
