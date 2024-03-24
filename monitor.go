package main

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/falcosecurity/client-go/pkg/api/outputs"
	"github.com/falcosecurity/client-go/pkg/client"
	"github.com/gogo/protobuf/jsonpb"
)

type Monitor struct {
	cert    string
	key     string
	ca      string
	logFile *os.File
	skip    []string
	logChan chan string
	end     chan bool
	ignore  bool
}

func newMonitor(c *Config) *Monitor {
	monitor := &Monitor{}
	monitor.cert = c.Cert
	monitor.key = c.Key
	monitor.ca = c.CA
	monitor.skip = c.Skip
	monitor.logChan = make(chan string)
	monitor.end = make(chan bool)
	return monitor
}

func (m *Monitor) start(nodes []Node) {
	for _, n := range nodes {
		go func(n Node) {
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				select {
				default:
					m.check(n)
				case <-m.end:
					return
				}
			}
		}(n)
	}
}

func (m *Monitor) stop() {
	m.end <- true
	m.logFile.Close()
}

func (m *Monitor) get() *Behavior {
	info, ok := <-m.logChan
	if !ok {
		return nil
	}
	return m.parse(info)
}

func (m *Monitor) check(n Node) {
	cli, err := client.NewForConfig(context.Background(), &client.Config{
		Hostname:   n.IP,
		Port:       5060,
		CertFile:   m.cert,
		KeyFile:    m.key,
		CARootFile: m.ca,
	})
	if err != nil {
		panic(err)
	}
	defer cli.Close()
	ctx := context.Background()
	outputsCli, _ := cli.Outputs()
	fcs, err := outputsCli.Get(ctx, &outputs.Request{})
	if err != nil {
		// log.Printf("error connecting to %s", n.IP)
		return
	}
	for {
		res, err := fcs.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Fatalf("error closing stream after EOF: %v", err)
		}
		if m.ignore {
			continue
		}
		out, _ := (&jsonpb.Marshaler{}).MarshalToString(res)
		out += "<br>" + n.IP
		m.logChan <- out
	}
}

func (m *Monitor) setIgnore(ignoreTime int) {
	m.ignore = true
	go func()  {
		duration := time.Duration(ignoreTime) * time.Second
		timer := time.After(duration)
		<- timer
		m.ignore = false
	}()
}

func (m *Monitor) parse(r string) *Behavior {
	var ok bool
	entry := &struct {
		Output       string                 `json:"output"`
		Tags         []string               `json:"tags"`
		OutputFields map[string]interface{} `json:"outputFields"`
	}{}
	split := strings.Split(r, "<br>")
	r = split[0]
	_ = json.Unmarshal([]byte(r), entry)
	if len(entry.Tags) != 1 {
		return nil
	}
	tag := entry.Tags[0]
	behavior := &Behavior{}
	behavior.Time = time.Now().Format("2006-01-02 15:04:05")
	behavior.Host = split[1]
	behavior.Origin, ok = entry.OutputFields["container.name"].(string)
	if !ok || behavior.Origin == "<NA>" {
		return nil
	}
	for _, s := range m.skip {
		if strings.Contains(behavior.Origin, s) {
			return nil
		}
	}
	switch tag {
	case "shadow_exec":
		behavior.Class = "exec"
		behavior.Object, ok = entry.OutputFields["proc.cmdline"].(string)
		if !ok {
			return nil
		}
	case "shadow_read":
		behavior.Class = "read"
		behavior.Object, ok = entry.OutputFields["fd.name"].(string)
		if !ok {
			return nil
		}
	case "shadow_write":
		behavior.Class = "write"
		behavior.Object, ok = entry.OutputFields["fd.name"].(string)
		if !ok {
			return nil
		}
	case "shadow_conn":
		behavior.Class = "conn"
		connection, ok := entry.OutputFields["fd.name"].(string)
		if !ok {
			return nil
		}
		behavior.Object = prsDst(connection)
	default:
		return nil
	}
	behavior.Output = entry.Output
	if !m.valid(behavior) {
		return nil
	}
	return behavior
}

func (m *Monitor) valid(b *Behavior) bool {
	valueOfInstance := reflect.ValueOf(*b)

	for i := 0; i < valueOfInstance.NumField(); i++ {
		field := valueOfInstance.Field(i)
		if field.Interface() == nil {
			return false
		}
	}
	return true
}
