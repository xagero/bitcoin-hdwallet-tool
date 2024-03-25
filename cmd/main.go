package main

import (
	"context"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"os"

	wallet "github.com/xagero/bitcoin-hdwallet-tool"

	"github.com/xagero/go-cli"
	"github.com/xagero/go-cli/command"
	"github.com/xagero/go-cli/view"
)

func main() {

	cmd := command.Construct("wallet:generate", "Generate bitcoin wallet address")

	cmd.AddOption("pass", command.OptionValueRequire, "Add password phrase")
	cmd.AddOption("mnemonic", command.OptionValueRequire, "Add mnemonic phrase")
	cmd.SetCallback(func() error {

		// Configure
		num := 10
		net := &chaincfg.MainNetParams
		compress := true

		password := cmd.GetOption("pass").Value()
		mnemonic := cmd.GetOption("mnemonic").Value()

		// Create wallet
		wt, _ := wallet.Construct(256, password, mnemonic)
		master, _ := wt.GetMasterKey()

		fmt.Println("")
		fmt.Printf("%s %s\n", "Bitcoin network:", net.Name)
		fmt.Printf("%s %s\n", "BIP39 Mnemonic:", wt.GetMnemonic())
		fmt.Printf("%s %s\n", "BIP39 Password:", wt.GetPassword())
		fmt.Printf("%s %x\n", "BIP39 Seed:", wt.GetSeed())
		fmt.Printf("%s %s\n", "BIP32 Root Key:", master.B58Serialize())

		bip49ViewTable := view.Construct("Path BIP49", "SegWit (P2WPKH-nested-in-P2SH)", "WIF (Wallet Import Format)")
		bip49ViewTable.SetHeading("\nBIP49 address")
		for i := 0; i < num; i++ {
			key, _ := wt.GetKey(0x80000031, 0x80000000, 0, 0, uint32(i))
			wif, address := key.GenerateSegWitNested(net, compress)

			bip49ViewTable.AddRow(key.GetPath(), address, wif)
		}
		bip49ViewTable.Render()

		bip84ViewTable := view.Construct("Path BIP84", "SegWit (P2WPKH, bech32)", "WIF (Wallet Import Format)")
		bip84ViewTable.SetHeading("\nBIP84 address")
		for i := 0; i < num; i++ {
			key, _ := wt.GetKey(0x80000054, 0x80000000, 0, 0, uint32(i))
			wif, address := key.GenerateBech32(net, compress)

			bip84ViewTable.AddRow(key.GetPath(), address, wif)
		}
		bip84ViewTable.Render()

		bip86ViewTable := view.Construct("Path BIP86", "Taproot (P2TR, bech32m)", "WIF (Wallet Import Format)")
		bip86ViewTable.SetHeading("\nBIP86 address")
		for i := 0; i < num; i++ {
			key, _ := wt.GetKey(0x80000056, 0x80000000, 0, 0, uint32(i))
			wif, address := key.GenerateTaproot(net, compress)

			bip86ViewTable.AddRow(key.GetPath(), address, wif)
		}
		bip86ViewTable.Render()

		return nil
	})

	name := "Console"
	desc := "Bitcoin HD wallet tool"
	version := "v0.1"

	console := cli.Construct(name, desc, version)
	console.AddCommand(cmd)

	if err := console.Run(context.Background(), os.Args); err != nil {
		fmt.Printf("Error encountered: %v\n", err)
	}
}
