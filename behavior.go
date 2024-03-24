package main

type Behavior struct {
	Time   string
	Class  string
	Host   string
	// from which container
	Origin string
	// File, Command or IP
	Object string
	// Output information, used for logging
	Output string
}

type BehaviorState int

const (
	NotMemberOfCluster BehaviorState = iota
	MemberOfCluster
	MemberOfConvertedCluster
	ConvertedMemberofConvertedCluster
)

func (b *Behavior) belongState(c *Cluster) BehaviorState {
	var belong bool
	var converted bool
	for _, n := range c.nodes {
		if b.Host == n.IP && n.converted {
			return ConvertedMemberofConvertedCluster
		} else if b.Host == n.IP {
			belong = true
		}
		if n.converted {
			converted = true
		}
	}
	if belong && converted {
		return MemberOfConvertedCluster
	} else if belong {
		return MemberOfCluster
	}
	return NotMemberOfCluster
}
