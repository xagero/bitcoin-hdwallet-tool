package wallet

import (
	"fmt"
	"sync"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"github.com/tyler-smith/go-bip39/wordlists"

	"github.com/xagero/go-helper/helper"
)

const (
	Zero       uint32 = 0
	Apostrophe uint32 = 0x80000000 // 0'
)

type Key struct {
	path     string
	bip32Key *bip32.Key
}

type HDWallet struct {

	// wallet data
	mnemonic string
	password string
	seed     []byte
	keys     map[string]*bip32.Key

	// sync mutex
	mux sync.RWMutex
}

// Construct return new HDWallet
func Construct(bitSize int, password, mnemonic string) (*HDWallet, error) {

	if helper.IsBlank(mnemonic) {
		bip39.SetWordList(wordlists.English)
		entropy, err := bip39.NewEntropy(bitSize)
		if err != nil {
			return nil, err
		}
		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
	}

	wt := new(HDWallet)

	wt.mnemonic = mnemonic
	wt.password = password
	wt.keys = make(map[string]*bip32.Key)

	return wt, nil
}

func (key *Key) GetPath() string {
	return key.path
}

// GetMnemonic return mnemonic string
func (wt *HDWallet) GetMnemonic() string {
	return wt.mnemonic
}

// GetPassword return password string
func (wt *HDWallet) GetPassword() string {
	return wt.password
}

// GetSeed return hashed seed
func (wt *HDWallet) GetSeed() []byte {
	if len(wt.seed) == 0 {
		wt.seed = bip39.NewSeed(wt.GetMnemonic(), wt.GetPassword())
	}
	return wt.seed
}

func (wt *HDWallet) getKey(path string) (*bip32.Key, bool) {
	wt.mux.RLock()
	defer wt.mux.RUnlock()

	key, ok := wt.keys[path]
	return key, ok
}

func (wt *HDWallet) setKey(path string, key *bip32.Key) {
	wt.mux.Lock()
	defer wt.mux.Unlock()

	wt.keys[path] = key
}

// GetMasterKey return Key
func (wt *HDWallet) GetMasterKey() (*bip32.Key, error) {
	path := "m"

	key, ok := wt.getKey(path)
	if ok {
		return key, nil
	}
	key, err := bip32.NewMasterKey(wt.GetSeed())
	if err != nil {
		return nil, err
	}

	wt.setKey(path, key)

	return key, nil
}

// GetKey return new Key
func (wt *HDWallet) GetKey(purpose, coinType, account, change, index uint32) (*Key, error) {

	returnKey := new(Key)

	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change, index)
	key, ok := wt.getKey(path)

	if ok {

		returnKey.path = path
		returnKey.bip32Key = key

		return returnKey, nil
	}

	parent, err := wt.GetChangeKey(purpose, coinType, account, change)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(index)
	if err != nil {
		return nil, err
	}

	wt.setKey(path, key)

	returnKey.path = path
	returnKey.bip32Key = key

	return returnKey, nil
}

// GetChangeKey return Key
func (wt *HDWallet) GetChangeKey(purpose, coinType, account, change uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'/%d`, purpose-Apostrophe, coinType-Apostrophe, account, change)

	key, ok := wt.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := wt.GetAccountKey(purpose, coinType, account)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(change)
	if err != nil {
		return nil, err
	}

	wt.setKey(path, key)

	return key, nil
}

// GetAccountKey return Key
func (wt *HDWallet) GetAccountKey(purpose, coinType, account uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe, account)

	key, ok := wt.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := wt.GetCoinTypeKey(purpose, coinType)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(account + Apostrophe)
	if err != nil {
		return nil, err
	}

	wt.setKey(path, key)

	return key, nil
}

// GetCoinTypeKey return Key
func (wt *HDWallet) GetCoinTypeKey(purpose, coinType uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'/%d'`, purpose-Apostrophe, coinType-Apostrophe)

	key, ok := wt.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := wt.GetPurposeKey(purpose)
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(coinType)
	if err != nil {
		return nil, err
	}

	wt.setKey(path, key)

	return key, nil
}

// GetPurposeKey return Key
func (wt *HDWallet) GetPurposeKey(purpose uint32) (*bip32.Key, error) {
	path := fmt.Sprintf(`m/%d'`, purpose-Apostrophe)

	key, ok := wt.getKey(path)
	if ok {
		return key, nil
	}

	parent, err := wt.GetMasterKey()
	if err != nil {
		return nil, err
	}

	key, err = parent.NewChildKey(purpose)
	if err != nil {
		return nil, err
	}

	wt.setKey(path, key)

	return key, nil
}
