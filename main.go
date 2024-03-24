package main

import (
	"os"
	"os/signal"
	"syscall"
)

var Change chan bool = make(chan bool, 1)

func main() {
	confFile := "config.json"
	config := loadConf(confFile)
	initLog(config)
	monitor := newMonitor(config)
	production := newProduction(config)
	shadow := newShadow(config)
	group := append(production.getDeployments(), "host")
	detector := newDetector(config, group, production, shadow)
	convertor := newConvertor(config, production, shadow)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupt
		Exit(monitor, detector, convertor)
	}()

	go monitor.start(production.nodes)
	go monitor.start(shadow.nodes)
	go detector.start()
	go convertor.periodReset()
	// ignore abnormal behavior in the first 1 minute
	monitor.setIgnore(30)
	for {
		select {
		case <-Change:
			monitor.setIgnore(120)
		default:
			behavior := monitor.get()
			if behavior == nil {
				continue
			}
			// logAll(behavior)
			// detector will caculate the suspicious score
			threat, strategy := detector.handle(behavior)
			switch strategy {
			case NoAction:
				continue
			case CleanCluster:
				logAbnormal(behavior)
				convertor.clean(threat)
			case ConvertCluster:
				logAbnormal(behavior)
				convertor.convert(threat)
			}
		}
	}
}

func Exit(m *Monitor, d *Detector, c *Convertor) {
	m.stop()
	d.stop()
	c.stop()
	os.Exit(0)
}

