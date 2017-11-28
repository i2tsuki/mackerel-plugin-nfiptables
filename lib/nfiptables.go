package mpnfiptables

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/coreos/go-iptables/iptables"
	mp "github.com/mackerelio/go-mackerel-plugin"
	"github.com/pkg/errors"
)

var ipt *iptables.IPTables

// NFIPTablesPlugin mackerel plugin for nf_iptables
type NFIPTablesPlugin struct {
	Prefix string
	Table  string
}

func init() {
	var err error
	ipt, err = iptables.New()
	if err != nil {
		fmt.Printf("err: %v", err)
		os.Exit(1)
	}
}

// FetchMetrics interface for mackerelplugin
func (p NFIPTablesPlugin) FetchMetrics() (map[string]float64, error) {
	stat := make(map[string]float64)

	chains, err := ipt.ListChains(p.Table)
	if err != nil {
		errors.Wrap(err, fmt.Sprintf("%v-%v failed: ", App.Name, App.Version))
		fmt.Printf("%v-%v failed: %v\n", App.Name, App.Version, err)
		os.Exit(1)
	}

	for _, chain := range chains {
		stats, err := ipt.Stats(p.Table, chain)
		if err != nil {
			errors.Wrap(err, fmt.Sprintf("%v-%v failed: ", App.Name, App.Version))
			fmt.Printf("%v-%v failed: %v\n", App.Name, App.Version, err)
			os.Exit(1)
		}
		var pkts int64
		var bytes int64
		for _, s := range stats {
			p, err := strconv.ParseInt(s[0], 10, 64)
			if err != nil {
				errors.Wrap(err, fmt.Sprintf("%v-%v failed: ", App.Name, App.Version))
				fmt.Printf("%v-%v failed: %v\n", App.Name, App.Version, err)
				os.Exit(1)
			}
			pkts += p

			b, err := strconv.ParseInt(s[1], 10, 64)
			if err != nil {
				errors.Wrap(err, fmt.Sprintf("%v-%v failed: ", App.Name, App.Version))
				fmt.Printf("%v-%v failed: %v\n", App.Name, App.Version, err)
				os.Exit(1)
			}
			bytes += b
		}
		stat[fmt.Sprintf("%s_pkts", chain)] = float64(pkts)
		stat[fmt.Sprintf("%s_bytes", chain)] = float64(bytes)
	}

	return stat, nil
}

// GraphDefinition interface for mackerelplugin
func (p NFIPTablesPlugin) GraphDefinition() (a map[string]mp.Graphs) {
	labelPrefix := strings.Title(p.Prefix)
	graphdef := make(map[string]mp.Graphs)

	chains, err := ipt.ListChains(p.Table)
	if err != nil {
		errors.Wrap(err, fmt.Sprintf("%v-%v failed: ", App.Name, App.Version))
		fmt.Printf("%v-%v failed: %v\n", App.Name, App.Version, err)
		os.Exit(1)
	}

	for _, chain := range chains {
		graphdef[chain] = mp.Graphs{
			Label: labelPrefix + " " + chain + " Stats",
			Unit:  "integer",
			Metrics: []mp.Metrics{
				{Name: chain + "_pkts", Label: "Packets", Diff: true, Stacked: false},
				{Name: chain + "_bytes", Label: "Bytes", Diff: true, Stacked: false},
			},
		}
	}

	return graphdef
}

// MetricKeyPrefix interface for PluginWithPrefix

// Do the plugin
func Do() {
	optPrefix := flag.String("metric-key-prefix", "nfiptables", "Prefix")
	optTable := flag.String("table", "filter", "Table (ex: nat, mangle...)")
	flag.Parse()

	nfipt := NFIPTablesPlugin{Prefix: *optPrefix, Table: *optTable}

	helper := mp.NewMackerelPlugin(nfipt)
	helper.Run()
}
