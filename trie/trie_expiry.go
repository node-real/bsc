package trie

import (
	"bytes"
	"fmt"
	"github.com/ethereum/go-ethereum/core/types"
)

func (t *Trie) TryLocalRevive(key []byte) ([]byte, error) {
	// Short circuit if the trie is already committed and not usable.
	if t.committed {
		return nil, ErrCommitted
	}

	key = keybytesToHex(key)
	val, newroot, didResolve, err := t.tryLocalRevive(t.root, key, 0, t.getRootEpoch())
	if err == nil && didResolve {
		t.root = newroot
		t.rootEpoch = t.currentEpoch
	}
	return val, err
}

func (t *Trie) tryLocalRevive(origNode node, key []byte, pos int, epoch types.StateEpoch) ([]byte, node, bool, error) {
	expired := t.epochExpired(origNode, epoch)
	switch n := (origNode).(type) {
	case nil:
		return nil, nil, false, nil
	case valueNode:
		return n, n, expired, nil
	case *shortNode:
		if len(key)-pos < len(n.Key) || !bytes.Equal(n.Key, key[pos:pos+len(n.Key)]) {
			// key not found in trie, but just revive for expand
			if t.renewNode(epoch, false, expired) {
				n = n.copy()
				n.setEpoch(t.currentEpoch)
				n.flags = t.newFlag()
				return nil, n, true, nil
			}
			return nil, n, false, nil
		}
		value, newnode, didResolve, err := t.tryLocalRevive(n.Val, key, pos+len(n.Key), epoch)
		if err == nil && t.renewNode(epoch, didResolve, expired) {
			n = n.copy()
			n.Val = newnode
			n.setEpoch(t.currentEpoch)
			n.flags = t.newFlag()
			didResolve = true
		}
		return value, n, didResolve, err
	case *fullNode:
		value, newnode, didResolve, err := t.tryLocalRevive(n.Children[key[pos]], key, pos+1, n.GetChildEpoch(int(key[pos])))
		if err == nil && t.renewNode(epoch, didResolve, expired) {
			n = n.copy()
			n.Children[key[pos]] = newnode
			n.setEpoch(t.currentEpoch)
			if newnode != nil {
				n.UpdateChildEpoch(int(key[pos]), t.currentEpoch)
			}
			n.flags = t.newFlag()
			didResolve = true
		}
		return value, n, didResolve, err
	case hashNode:
		child, err := t.resolveAndTrack(n, key[:pos])
		if err != nil {
			return nil, n, true, err
		}

		if err = t.resolveEpochMetaAndTrack(child, epoch, key[:pos]); err != nil {
			return nil, n, true, err
		}
		value, newnode, _, err := t.tryLocalRevive(child, key, pos, epoch)
		return value, newnode, true, err
	default:
		panic(fmt.Sprintf("%T: invalid node: %v", origNode, origNode))
	}
}
