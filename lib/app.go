package mpnfiptables

type app struct {
	Name    string
	Version string
}

// App include application name and version
var App = app{
	Name:    "mackerel-plugin-nfiptables",
	Version: "0.1.0",
}
