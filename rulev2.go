package main

import (
    "strings"
	"github.com/golang/glog"
	"github.com/hbollon/go-edlib"
)

// 1. the length of common formalized token
// 2. common formalized token

type RuleV2 struct {
	Group string   `json:"group"`
	Exec  []string `json:"exec"`
	Read  []string `json:"read"`
	Write []string `json:"write"`
}

// 1. add the baseline into rule group
// 2. fuzzy search the similar baseline with threshold of 0.6

func (r *RuleV2) updateRead(path string) {
	r.Read = append(r.Read, path)
}

func (r *RuleV2) updateWrite(path string) {
	r.Write = append(r.Write, path)
}

func (r *RuleV2) updateExec(cmd string) {
	r.Exec = append(r.Exec, cmd)
}

func (r *RuleV2) fuzzy(target, class string, threshold float32) bool {
	glog.V(2).Infof("Fuzzy search target: %v", target)
	
	var res []string
	var err error
	switch class {
	case "exec":
		res, err = edlib.FuzzySearchSetThreshold(target, r.Exec, 1, threshold, edlib.Levenshtein)
	case "read":
		res, err = edlib.FuzzySearchSetThreshold(target, r.Read, 1, threshold, edlib.Levenshtein)
	case "write":
		res, err = edlib.FuzzySearchSetThreshold(target, r.Write, 1, threshold, edlib.Levenshtein)
	}

	if err != nil {
		glog.Errorf("Fuzzy search error: %v", err)
	}
	if len(res) > 0 {
		glog.V(2).Infof("Fuzzy search result: %v", res)
		return true
	}
	glog.V(2).Infof("No fuzzy search result.")
	return false
}
