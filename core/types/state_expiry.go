package types

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/log"
)

const (
	StateExpiryPruneLevel0 = iota // StateExpiryPruneLevel0 is the default level, it will prune all expired snapshot kvs and trie nodes, but it will access more times in tire when execution. It not supports in HBSS.
	StateExpiryPruneLevel1        // StateExpiryPruneLevel1 it left all snapshot & epoch meta for performance friendly.
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
	EnableRemoteMode  bool `rlp:"optional"` // when enable remoteDB mode, it will register specific RPC for partial proof and keep sync behind for safety proof
}

// EnableExpiry when enable remote mode, it just check param
func (s *StateExpiryConfig) EnableExpiry() bool {
	if s == nil {
		return false
	}
	return s.Enable && !s.EnableRemoteMode
}

// EnableRemote when enable remote mode, it just check param
func (s *StateExpiryConfig) EnableRemote() bool {
	if s == nil {
		return false
	}
	return s.Enable && s.EnableRemoteMode
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
	if s.EnableRemoteMode && !newCfg.EnableRemoteMode {
		return errors.New("disable state expiry  EnableRemoteMode is dangerous after enabled")
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
		return "State Expiry Disable."
	}
	if s.Enable && s.EnableRemoteMode {
		return "State Expiry Enable in RemoteMode, it will not expired any state."
	}
	return fmt.Sprintf("Enable State Expiry, RemoteEndpoint: %v, StateEpoch: [%v|%v|%v], StateScheme: %v, PruneLevel: %v, EnableLocalRevive: %v.",
		s.FullStateEndpoint, s.StateEpoch1Block, s.StateEpoch2Block, s.StateEpochPeriod, s.StateScheme, s.PruneLevel, s.EnableLocalRevive)
}

// ShouldKeep1EpochBehind when enable state expiry, keep remoteDB behind the latest only 1 epoch blocks
func (s *StateExpiryConfig) ShouldKeep1EpochBehind(remote uint64, local uint64) (bool, uint64) {
	if !s.EnableRemoteMode {
		return false, remote
	}
	if remote <= local {
		return false, remote
	}

	// if in epoch0, just sync
	if remote < s.StateEpoch1Block {
		return false, remote
	}

	// if in epoch1, behind StateEpoch2Block-StateEpoch1Block
	if remote < s.StateEpoch2Block {
		if remote-(s.StateEpoch2Block-s.StateEpoch1Block) <= local {
			return true, 0
		}
		return false, remote - (s.StateEpoch2Block - s.StateEpoch1Block)
	}

	// if in >= epoch2, behind StateEpochPeriod
	if remote-s.StateEpochPeriod <= local {
		return true, 0
	}
	return false, remote - s.StateEpochPeriod
}
