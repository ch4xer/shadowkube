package main

import (
	"time"
)

type Convertor struct {
	production *Cluster
	shadow     *Cluster
	ifDetect   bool
	aliveTime  int
	maxConvert int
	reportAPI  string
	forceEnd   chan bool
}

func newConvertor(c *Config, production *Cluster, shadow *Cluster) *Convertor {
	return &Convertor{
		production: production,
		shadow:     shadow,
		ifDetect:   c.Detect,
		aliveTime:  c.AliveTime,
		maxConvert: c.MaxConvert,
		reportAPI:  c.Report,
		forceEnd:   make(chan bool),
	}
}

func (c *Convertor) convert(threat ThreatInfo) {
	if c.production.countConvertedNode() >= c.maxConvert {
		logInfo("Could not convert more nodes, skip")
		return
	}

	if c.production.convert(threat, c.shadow.master) {
		logInfo("Convert production done")
		Change <- true
		// alarm(c.reportAPI)
		// launch a timer to reset all
		go c.resetTimer()
	} else {
		logInfo("Convert production failed")
	}
}

func (c *Convertor) clean(threat ThreatInfo) {
	if c.production.clean(threat) {
		logInfo("Clean production master done")
	} else {
		logInfo("Clean production master failed")
	}
}

func (c *Convertor) resetTimer() {
	duration := time.Duration(c.aliveTime) * time.Minute
	timer := time.After(duration)
	select {
	case <-c.forceEnd:
		return
	case <-timer:
		c.resetAll()
	}
}

// reset all for every period, only for reset shadow
// in case that no abnormal behavior detected in production
func (c *Convertor) periodReset() {
	if c.ifDetect == false {
		return
	}
	duration := time.Duration(120) * time.Minute
	ticker := time.NewTicker(duration)
	defer ticker.Stop()
	for range ticker.C {
		select {
		case <-c.forceEnd:
			return
		default:
			c.resetAll()
		}
	}
}

func (c *Convertor) resetAll() {
	c.production.reset()
	c.shadow.reset()
	logInfo("Reset done")
	Change <- true
}

func (c *Convertor) stop() {
	if c.production.countConvertedNode() > 0 {
		c.forceEnd <- true
	}
}
