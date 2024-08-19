package beaconserver

import (
	"net/http"

	"github.com/gorilla/mux"
	"github.com/prysmaticlabs/prysm/v5/api/server"
)

const (
	DefaultBSCNodeURL = "http://127.0.0.1:8545"
	DefaultHostPort   = "0.0.0.0:8686"
)

type Config struct {
	Enable     bool
	BSCNodeURL string
	HostPort   string
}

func defaultConfig() *Config {
	return &Config{
		Enable:     false,
		BSCNodeURL: DefaultBSCNodeURL,
		HostPort:   DefaultHostPort,
	}
}

type Service struct {
	cfg    *Config
	router *mux.Router
}

func NewService(cfg *Config) *Service {
	cfgs := defaultConfig()
	if cfg.BSCNodeURL != "" {
		cfgs.BSCNodeURL = cfg.BSCNodeURL
	}
	if cfg.HostPort != "" {
		cfgs.HostPort = cfg.HostPort
	}
	Init(cfg.BSCNodeURL)
	router := newRouter()

	return &Service{
		cfg:    cfgs,
		router: router,
	}
}

func (s *Service) Run() {
	_ = http.ListenAndServe(s.cfg.HostPort, s.router)
}

func newRouter() *mux.Router {
	r := mux.NewRouter()
	r.Use(server.NormalizeQueryValuesHandler)
	for _, e := range endpoints() {
		r.HandleFunc(e.path, e.handler).Methods(e.methods...)
	}
	return r
}

type endpoint struct {
	path    string
	handler http.HandlerFunc
	methods []string
}

func endpoints() []endpoint {
	return []endpoint{
		{
			path:    versionMethod,
			handler: VersionMethod,
			methods: []string{http.MethodGet},
		},
		{
			path:    specMethod,
			handler: SpecMethod,
			methods: []string{http.MethodGet},
		},
		{
			path:    genesisMethod,
			handler: GenesisMethod,
			methods: []string{http.MethodGet},
		},
		{
			path:    sidecarsMethodPrefix,
			handler: SidecarsMethod,
			methods: []string{http.MethodGet},
		},
	}
}
