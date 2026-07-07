// Copyright (c) 2025–2026 André Gustavo Leão de Melo Ataíde (had-nu). All rights reserved.
// SPDX-License-Identifier: AGPL-3.0-or-later OR LicenseRef-Wardex-Commercial

package ethanchor

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/had-nu/immutable-provenance/manifest"
)

// Client wraps the Ethereum RPC connection and details.
type Client struct {
	rpcClient    *ethclient.Client
	contractAddr common.Address
	parsedABI    abi.ABI
}

// NewClient initializes a connection to the Ethereum/Polygon RPC node.
func NewClient(rpcURL, contractAddrHex string) (*Client, error) {
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to Ethereum node: %w", err)
	}

	contractAddr := common.HexToAddress(contractAddrHex)
	parsedABI, err := abi.JSON(strings.NewReader(ProvenanceAnchorABI))
	if err != nil {
		return nil, fmt.Errorf("parsing contract ABI: %w", err)
	}

	return &Client{
		rpcClient:    client,
		contractAddr: contractAddr,
		parsedABI:    parsedABI,
	}, nil
}

// Anchor submits the manifest root hash to the smart contract via a transaction.
func (c *Client) Anchor(ctx context.Context, privKeyHex string, rootHash string) (string, error) {
	privKeyHex = strings.TrimPrefix(privKeyHex, "0x")
	privKey, err := crypto.HexToECDSA(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	publicKey := privKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("cannot assert type of public key to *ecdsa.PublicKey")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := c.rpcClient.PendingNonceAt(ctx, fromAddress)
	if err != nil {
		return "", fmt.Errorf("getting pending nonce: %w", err)
	}

	gasPrice, err := c.rpcClient.SuggestGasPrice(ctx)
	if err != nil {
		return "", fmt.Errorf("suggesting gas price: %w", err)
	}

	chainID, err := c.rpcClient.NetworkID(ctx)
	if err != nil {
		return "", fmt.Errorf("getting chain ID: %w", err)
	}

	cleanHash := manifest.StripHashPrefix(rootHash)
	hashBytes, err := hex.DecodeString(cleanHash)
	if err != nil || len(hashBytes) != 32 {
		return "", fmt.Errorf("invalid root hash hex length (must be 32 bytes): %w", err)
	}

	var hashParam [32]byte
	copy(hashParam[:], hashBytes)

	data, err := c.parsedABI.Pack("anchor", hashParam)
	if err != nil {
		return "", fmt.Errorf("packing contract data: %w", err)
	}

	msg := ethereum.CallMsg{
		From:     fromAddress,
		To:       &c.contractAddr,
		GasPrice: gasPrice,
		Value:    big.NewInt(0),
		Data:     data,
	}
	gasLimit, err := c.rpcClient.EstimateGas(ctx, msg)
	if err != nil {
		gasLimit = uint64(100000)
	}

	tx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce,
		GasPrice: gasPrice,
		Gas:      gasLimit,
		To:       &c.contractAddr,
		Value:    big.NewInt(0),
		Data:     data,
	})

	signedTx, err := types.SignTx(tx, types.NewLondonSigner(chainID), privKey)
	if err != nil {
		return "", fmt.Errorf("signing transaction: %w", err)
	}

	err = c.rpcClient.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("sending transaction: %w", err)
	}

	return signedTx.Hash().Hex(), nil
}

// Verify queries the smart contract to check if the root hash is anchored.
func (c *Client) Verify(ctx context.Context, rootHash string) (time.Time, bool, error) {
	cleanHash := manifest.StripHashPrefix(rootHash)
	hashBytes, err := hex.DecodeString(cleanHash)
	if err != nil || len(hashBytes) != 32 {
		return time.Time{}, false, fmt.Errorf("invalid root hash hex length (must be 32 bytes): %w", err)
	}

	var hashParam [32]byte
	copy(hashParam[:], hashBytes)

	data, err := c.parsedABI.Pack("proofs", hashParam)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("packing contract query: %w", err)
	}

	msg := ethereum.CallMsg{
		To:   &c.contractAddr,
		Data: data,
	}

	res, err := c.rpcClient.CallContract(ctx, msg, nil)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("calling smart contract: %w", err)
	}

	out, err := c.parsedABI.Unpack("proofs", res)
	if err != nil || len(out) == 0 {
		return time.Time{}, false, fmt.Errorf("unpacking contract output: %w", err)
	}

	timestamp, ok := out[0].(*big.Int)
	if !ok {
		return time.Time{}, false, fmt.Errorf("invalid output type decoded from smart contract")
	}

	if timestamp.Cmp(big.NewInt(0)) == 0 {
		return time.Time{}, false, nil
	}

	anchorTime := time.Unix(timestamp.Int64(), 0).UTC()
	return anchorTime, true, nil
}
