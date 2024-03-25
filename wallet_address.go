package wallet

import (
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// GenerateSegWitNested generate address in SegWit (P2WPKH-nested-in-P2SH)
func (key *Key) GenerateSegWitNested(net *chaincfg.Params, compress bool) (string, string) {

	// Generate new pair from bytes
	privateKey, _ := btcec.PrivKeyFromBytes(key.bip32Key.Key)

	// Generate WIF
	btcwif, _ := btcutil.NewWIF(privateKey, net, compress)

	hash160 := btcutil.Hash160(btcwif.SerializePubKey())
	addressWitness, _ := btcutil.NewAddressWitnessPubKeyHash(hash160, &chaincfg.MainNetParams)
	payToAddress, _ := txscript.PayToAddrScript(addressWitness)
	addressScriptHash, _ := btcutil.NewAddressScriptHash(payToAddress, &chaincfg.MainNetParams)

	return btcwif.String(), addressScriptHash.EncodeAddress()
}

// GenerateBech32 generate address in SegWit (P2WPKH, bech32)
func (key *Key) GenerateBech32(net *chaincfg.Params, compress bool) (string, string) {

	// Generate new pair from bytes
	privateKey, _ := btcec.PrivKeyFromBytes(key.bip32Key.Key)

	// Generate WIF
	btcwif, _ := btcutil.NewWIF(privateKey, net, compress)

	// Encode to hash160 (ripemd160)
	hash160 := btcutil.Hash160(btcwif.SerializePubKey())
	addressWitness, _ := btcutil.NewAddressWitnessPubKeyHash(hash160, &chaincfg.MainNetParams)

	return btcwif.String(), addressWitness.EncodeAddress()
}

func (key *Key) GenerateTaproot(net *chaincfg.Params, compress bool) (string, string) {

	// Generate new pair from bytes
	privateKey, publicKey := btcec.PrivKeyFromBytes(key.bip32Key.Key)

	// Generate WIF
	btcwif, _ := btcutil.NewWIF(privateKey, net, compress)

	tapKey := txscript.ComputeTaprootKeyNoScript(publicKey)
	addressTaproot, _ := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &chaincfg.MainNetParams)

	return btcwif.String(), addressTaproot.EncodeAddress()
}
