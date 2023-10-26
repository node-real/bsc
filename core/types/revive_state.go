package types

type ReviveStorageProof struct {
	Key       string   `json:"key"`
	PrefixKey string   `json:"prefixKey"`
	Proof     []string `json:"proof"`
}

type ReviveResult struct {
	Err          string               `json:"err"`
	StorageProof []ReviveStorageProof `json:"storageProof"`
	BlockNum     uint64               `json:"blockNum"`
}

func NewReviveErrResult(err error, block uint64) *ReviveResult {
	var errRet string
	if err != nil {
		errRet = err.Error()
	}
	return &ReviveResult{
		Err:      errRet,
		BlockNum: block,
	}
}

func NewReviveResult(proof []ReviveStorageProof, block uint64) *ReviveResult {
	return &ReviveResult{
		StorageProof: proof,
		BlockNum:     block,
	}
}
