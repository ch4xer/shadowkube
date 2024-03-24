package main

import (
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Detector receive log, update or compare the ruleset
type Detector struct {
	Rules      []Rule `json:"rules"`
	production *Cluster
	shadow     *Cluster
	ruleFile   *os.File
	ifDetect   bool
	suspicious float64
	threshold  float64
	winTime    int
	end        chan bool
}

type ThreatInfo struct {
	host   string
	origin string
	object string
}

type NewContainerState int

const (
	NotNew NewContainerState = iota
	NewOnWorker
	NewOnMaster
)

func newDetector(c *Config, groups []string, production, shadow *Cluster) *Detector {
	d := &Detector{}
	d.production = production
	d.shadow = shadow
	d.ruleFile, _ = os.OpenFile(c.Rule, os.O_CREATE|os.O_RDWR, 0777)
	fileInfo, _ := os.Stat(c.Rule)
	d.suspicious = 0
	d.winTime = c.WinTime
	d.threshold = c.Threshold
	d.end = make(chan bool, 1)
	if fileInfo.Size() == 0 {
		// init empty ruleset
		for _, g := range groups {
			rule := Rule{
				Group: g,
				Exec:  map[string][]string{},
				Read:  []string{},
				Write: []string{},
				Conn:  []string{},
			}
			d.Rules = append(d.Rules, rule)
		}
		logInfo("Init ruleset: %s", d.Rules)
	} else {
		json.NewDecoder(d.ruleFile).Decode(d)
		elements := make(map[string]bool)
		for _, r := range d.Rules {
			elements[r.Group] = true
		}
		for _, g := range groups {
			if _, ok := elements[g]; !ok {
				rule := Rule{
					Group: g,
					Exec:  map[string][]string{},
					Read:  []string{},
					Write: []string{},
					Conn:  []string{},
				}
				d.Rules = append(d.Rules, rule)
			}
		}
		logInfo("Load ruleset: %s", d.Rules)
	}

	d.ifDetect = c.Detect
	return d
}

func (d *Detector) handle(behavior *Behavior) (ThreatInfo, Strategy) {
	threatInfo := ThreatInfo{}
	strategy := NoAction
	if d.ifDetect {
		shadowBelongState := behavior.belongState(d.shadow)
		productionBelongState := behavior.belongState(d.production)
		if productionBelongState == ConvertedMemberofConvertedCluster {
			// if the behavior belongs to shadow,
			// or the behavior belongs to a converted node from production
			// log it
			logAbnormal(behavior)
		} else if shadowBelongState == MemberOfCluster {
			// log all behavior from shadow cluster
			logAbnormal(behavior)
		} else if productionBelongState == MemberOfConvertedCluster {
			// if the behavior belongs to production
			// and the node has not been converted
			// and the production has been converted
			// ignore it (we limit the max convertion to 1)
		} else {
			threatInfo.host = behavior.Host
			threatInfo.origin = behavior.Origin
			threatInfo.object = behavior.Object
			containerState := d.checkNewContainerState(behavior)
			switch containerState {
			case NewOnMaster:
				strategy = CleanCluster
			case NewOnWorker:
				strategy = ConvertCluster
			case NotNew:
				// calculate the suspicious score
				// and determine whether the behavior is malicious
				d.calculate(behavior)
				if d.suspicious > d.threshold {
					strategy = ConvertCluster
				}
			}
		}
	} else {
		// learn from normal behavior
		d.update(behavior)
	}
	return threatInfo, strategy
}

func (d *Detector) isClusterChanged(behavior *Behavior) bool {
	for _, n := range d.production.convertedNodes {
		if behavior.Host == n.IP {
			if n.converted {
				return true
			}
		}
	}
	return false
}

func (d *Detector) start() {
	if d.ifDetect {
		go d.resetSuspicious()
	}
}

// reset accumulated suspicious score every winTime seconds
func (d *Detector) resetSuspicious() {
	ticker := time.NewTicker(time.Duration(d.winTime) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		select {
		default:
			d.suspicious = 0
		case <-d.end:
			logInfo("Stop detector.")
			return
		}
	}
}

func (d *Detector) findRuleByName(origin string) *Rule {
	for i := range d.Rules {
		if strings.Contains(origin, d.Rules[i].Group) {
			// the pod belongs to the group
			return &d.Rules[i]
		}
	}
	return nil
}

// Update update the ruleset
func (d *Detector) update(b *Behavior) {
	r := d.findRuleByName(b.Origin)
	if r == nil {
		logInfo("There might be malicious container !!")
		logInfo("No rule matched: %s", b)
		return
	}
	switch b.Class {
	case "exec":
		if r.updExec(b.Object) {
			// log.Printf("Update Exec rule: %s", behavior.Object)
			logInfo("Update Exec rule: %s", b)
		}
	case "read":
		if r.updRd(b.Object) {
			logInfo("Update Read rule: %s", b)
		}
	case "write":
		if r.updWrt(b.Object) {
			logInfo("Update Write rule: %s", b)
		}
	case "conn":
		if r.updConn(b.Object) {
			logInfo("Update Conn rule: %s", b)
		}
	}
}

func (d *Detector) checkNewContainerState(b *Behavior) NewContainerState {
	if d.findRuleByName(b.Origin) == nil {
		if b.Host == d.production.master.IP {
			logInfo("Malicious container on master node")
			return NewOnMaster
		} else {
			logInfo("Malicious container on worker node")
			return NewOnWorker
		}
	}
	return NotNew
}

// calculate Calculate the suspicious score of the behavior
func (d *Detector) calculate(b *Behavior) {
	r := d.findRuleByName(b.Origin)
	switch b.Class {
	case "exec":
		s := r.matchExecRule(b.Object)
		d.accumulate(s, b)
	case "read":
		s := r.matchReadRule(b.Object)
		d.accumulate(s, b)
	case "write":
		s := r.matchWriteRule(b.Object)
		d.accumulate(s, b)
	case "conn":
		s := r.matchConnectionRule(b.Object)
		d.accumulate(s, b)
	}
}

func (d *Detector) accumulate(s float64, b *Behavior) {
	if s > 0.1 {
		d.suspicious += s
		logInfo("Suspicious %f: %s", d.suspicious, b)
		logAbnormal(b)
	}
}

func (d *Detector) stop() {
	if !d.ifDetect {
		// dump ruleset into file
		d.ruleFile.Truncate(0)
		d.ruleFile.Seek(0, 0)
		encoder := json.NewEncoder(d.ruleFile)
		encoder.SetIndent("", "  ")
		err := encoder.Encode(d)
		if err != nil {
			panic(err)
		}
		logInfo("Dump ruleset.")
	} else {
		d.end <- true
	}
}
