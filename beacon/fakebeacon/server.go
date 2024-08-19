package fakebeacon

import (
	"net/http"

	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/gorilla/mux"
	"github.com/prysmaticlabs/prysm/v5/api/server"
)

const (
	DefaultHostPort = "0.0.0.0:8686"
)

type Config struct {
	Enable   bool
	HostPort string
}

func defaultConfig() *Config {
	return &Config{
		Enable:   false,
		HostPort: DefaultHostPort,
	}
}

type Service struct {
	cfg     *Config
	router  *mux.Router
	backend ethapi.Backend
}

func NewService(cfg *Config, backend ethapi.Backend) *Service {
	cfgs := defaultConfig()
	if cfg.HostPort != "" {
		cfgs.HostPort = cfg.HostPort
	}

	s := &Service{
		cfg:     cfgs,
		backend: backend,
	}
	router := s.newRouter()
	s.router = router
	return s
}

func (s *Service) Run() {
	_ = http.ListenAndServe(s.cfg.HostPort, s.router)
}

func (s *Service) newRouter() *mux.Router {
	r := mux.NewRouter()
	r.Use(server.NormalizeQueryValuesHandler)
	for _, e := range s.endpoints() {
		r.HandleFunc(e.path, e.handler).Methods(e.methods...)
	}
	return r
}

type endpoint struct {
	path    string
	handler http.HandlerFunc
	methods []string
}

func (s *Service) endpoints() []endpoint {
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
			handler: s.SidecarsMethod,
			methods: []string{http.MethodGet},
		},
	}
}
