package main

import (
	"math"
	"strings"
)

type Rule struct {
	Group string              `json:"group"`
	Exec  map[string][]string `json:"exec"`
	Read  []string            `json:"read"`
	Write []string            `json:"write"`
	Conn  []string            `json:"conn"`
}

func (r *Rule) updateWrite(file string) bool {
	for _, s := range r.Write {
		if strings.Contains(file, s) {
			return false
		}
	}
	ifupdated := false
	r.Write, ifupdated = findLongestPrefix(r.Write, file)
	return ifupdated
}

func (r *Rule) updateRead(file string) bool {
	for _, s := range r.Read {
		if strings.Contains(file, s) {
			return false
		}
	}
	ifupdated := false
	r.Read, ifupdated = findLongestPrefix(r.Read, file)
	return ifupdated
}

func (r *Rule) updateExec(cmd string) bool {
	bin := strings.Split(cmd, " ")[0]
	arg := strings.Join(strings.Split(cmd, " ")[1:], " ")
	ifupdated := false
	// if bin is the key of the map,
	// then the value is the longest common prefix of the bin
	if _, ok := r.Exec[bin]; ok {
		for _, s := range r.Exec[bin] {
			if strings.Contains(arg, s) {
				return false
			}
		}
		// no matched rule, start to find min common prefix
		r.Exec[bin], ifupdated = findLongestPrefix(r.Exec[bin], arg)
	} else {
		r.Exec[bin] = []string{}
		r.Exec[bin], ifupdated = findLongestPrefix(r.Exec[bin], arg)
	}
	return ifupdated
}

func (r *Rule) updateConnect(addr string) bool {
	for _, s := range r.Conn {
		if addr == s {
			return false
		}
	}
	r.Conn = append(r.Conn, addr)
	return true
}

func (r *Rule) matchWriteRule(file string) float64 {
	return hitRule(r.Write, file)
}

func (r *Rule) matchReadRule(file string) float64 {
	return hitRule(r.Read, file)
}

func (r *Rule) matchExecRule(cmd string) float64 {
	bin := strings.Split(cmd, " ")[0]
	arg := strings.Join(strings.Split(cmd, " ")[1:], " ")
	if _, ok := r.Exec[bin]; ok {
		rules := r.Exec[bin]
		return hitRule(rules, arg)
	}
	// execute new command is highly suspicious
	return 1
}

func (r *Rule) matchConnectionRule(addr string) float64 {
	for _, s := range r.Conn {
		if s == addr {
			return 0
		}
	}
	return 0.5
}

func findLongestPrefix(rules []string, obj string) ([]string, bool) {
	resultRules := rules
	if len(obj) == 0 {
		return resultRules, false
	}
	if len(resultRules) == 0 {
		resultRules = append(resultRules, obj)
		return resultRules, true
	}
	thresholdsValue := 15
	thresholdsPropotion := 0.5
	longest := 0
	var longestPrefix string
	var matched int

	for i, s := range resultRules {
		var minLen int
		if len(s) > len(obj) {
			minLen = len(obj)
		} else {
			minLen = len(s)
		}
		var commonPrefix string
		for j := 0; j < minLen; j++ {
			if s[j] == obj[j] {
				commonPrefix += string(s[j])
			} else {
				break
			}
		}
		if len(commonPrefix) > longest {
			longest = len(commonPrefix)
			longestPrefix = commonPrefix
			matched = i
		}
	}

	// only update when the longest prefix is longer than thresholds
	// object * proportion > min_thresholds
	a := float64(len(obj)) * thresholdsPropotion
	b := float64(thresholdsValue)
	if a > b {
		// use thresholdsPropotion as benchmark
		if float64(longest) < a {
			resultRules = append(resultRules, obj)
		} else {
			resultRules[matched] = longestPrefix
		}
	} else {
		// use thresholdsValue as benchmark
		if float64(longest) < b {
			resultRules = append(resultRules, obj)
		} else {
			resultRules[matched] = longestPrefix
		}
	}
	return resultRules, true
}

func hitRule(rules []string, obj string) float64 {
	minSuspicious := float64(10)
	if len(rules) == 0 {
		return 1
	}
	for _, s := range rules {
		length := len(s)
		obj := obj
		// make object the same length as rule
		if len(obj) < length {
			padLen := length - len(obj)
			padding := make([]byte, padLen)
			for i := range padding {
				padding[i] = 0
			}
			obj += string(padding)
		} else {
			obj = obj[:length]
		}

		deviation := float64(0)
		base := float64(0)
		for i := range s {
			deviation = deviation*10 + math.Abs(float64(s[i]-obj[i]))
		}
		for i := range s {
			base = base*10 + float64(s[i])
		}
		suspicious := deviation / base
		if suspicious < minSuspicious {
			minSuspicious = suspicious
		}
		// if deviation/base < 0.2 {
		// 	log.Printf("Hit rule: %s", object)
		// 	return true
		// }
	}
	// in case of empty ruleset
	if minSuspicious == float64(10) {
		return 0
	}
	return minSuspicious
}
