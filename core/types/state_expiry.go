package types

import (
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/log"
	"strings"
)

const (
	StateExpiryPruneLevel0 = iota // StateExpiryPruneLevel0 is for HBSS, in HBSS we cannot prune any expired snapshot, it need rebuild trie for old tire node prune, it also cannot prune any shared trie node too.
	StateExpiryPruneLevel1        // StateExpiryPruneLevel1 is the default level, it left some expired snapshot meta for performance friendly.
	StateExpiryPruneLevel2        // StateExpiryPruneLevel2 will prune all expired snapshot kvs and trie nodes, but it will access more times in tire when execution. TODO(0xbundler): will support it later
)

type StateExpiryConfig struct {
	Enable            bool
	FullStateEndpoint string
	StateScheme       string
	PruneLevel        uint8
	StateEpoch1Block  uint64
	StateEpoch2Block  uint64
	StateEpochPeriod  uint64
	EnableLocalRevive bool
}

func (s *StateExpiryConfig) EnableExpiry() bool {
	if s == nil {
		return false
	}
	return s.Enable
}

func (s *StateExpiryConfig) Validation() error {
	if s == nil || !s.Enable {
		return nil
	}

	s.FullStateEndpoint = strings.TrimSpace(s.FullStateEndpoint)
	if s.StateEpoch1Block == 0 ||
		s.StateEpoch2Block == 0 ||
		s.StateEpochPeriod == 0 {
		return errors.New("StateEpoch1Block or StateEpoch2Block or StateEpochPeriod cannot be 0")
	}

	if s.StateEpoch1Block >= s.StateEpoch2Block {
		return errors.New("StateEpoch1Block cannot >= StateEpoch2Block")
	}

	if s.StateEpochPeriod < DefaultStateEpochPeriod {
		log.Warn("The State Expiry state period is too small and may result in frequent expiration affecting performance",
			"input", s.StateEpochPeriod, "default", DefaultStateEpochPeriod)
	}

	return nil
}

func (s *StateExpiryConfig) CheckCompatible(newCfg *StateExpiryConfig) error {
	if s == nil || newCfg == nil {
		return nil
	}

	if s.Enable && !newCfg.Enable {
		return errors.New("disable state expiry is dangerous after enabled, expired state may pruned")
	}

	if err := s.CheckStateEpochCompatible(newCfg.StateEpoch1Block, newCfg.StateEpoch2Block, newCfg.StateEpochPeriod); err != nil {
		return err
	}

	if s.StateScheme != newCfg.StateScheme {
		return errors.New("StateScheme is incompatible")
	}

	if s.PruneLevel != newCfg.PruneLevel {
		return errors.New("state expiry PruneLevel is incompatible")
	}

	return nil
}

func (s *StateExpiryConfig) CheckStateEpochCompatible(StateEpoch1Block, StateEpoch2Block, StateEpochPeriod uint64) error {
	if s == nil {
		return nil
	}

	if s.StateEpoch1Block != StateEpoch1Block ||
		s.StateEpoch2Block != StateEpoch2Block ||
		s.StateEpochPeriod != StateEpochPeriod {
		return fmt.Errorf("state Epoch info is incompatible, StateEpoch1Block: [%v|%v], StateEpoch2Block: [%v|%v], StateEpochPeriod: [%v|%v]",
			s.StateEpoch1Block, StateEpoch1Block, s.StateEpoch2Block, StateEpoch2Block, s.StateEpochPeriod, StateEpochPeriod)
	}

	return nil
}

func (s *StateExpiryConfig) String() string {
	if !s.Enable {
		return "State Expiry Disable"
	}
	return fmt.Sprintf("Enable State Expiry, RemoteEndpoint: %v, StateEpoch: [%v|%v|%v], StateScheme: %v, PruneLevel: %v, EnableLocalRevive: %v",
		s.FullStateEndpoint, s.StateEpoch1Block, s.StateEpoch2Block, s.StateEpochPeriod, s.StateScheme, s.PruneLevel, s.EnableLocalRevive)
}
