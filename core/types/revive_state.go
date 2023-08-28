package types

type ReviveStorageProof struct {
	Key       string   `json:"key"`
	PrefixKey string   `json:"prefixKey"`
	Proof     []string `json:"proof"`
}
