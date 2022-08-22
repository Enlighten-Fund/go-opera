// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package evmcore

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"

	"github.com/Fantom-foundation/go-opera/txtrace"

	"github.com/Fantom-foundation/go-opera/utils/signers/gsignercache"
	"github.com/Fantom-foundation/go-opera/utils/signers/internaltx"
)

var (
	ProcessingInternalTransaction bool
	PrevBlockNumber               uint64 = 0
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     DummyChain          // Canonical block chain
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc DummyChain) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(
	block *EvmBlock, statedb *state.StateDB, cfg vm.Config, usedGas *uint64, onNewLog func(*types.Log, *state.StateDB),
) (
	receipts types.Receipts, allLogs []*types.Log, skipped []uint32, err error,
) {
	defer func(start time.Time) {
		fmt.Printf("Execution state_process, block_number = %v ,cost time = %v\n", strconv.FormatUint(block.NumberU64(), 10), time.Since(start))
	}(time.Now())
	skipped = make([]uint32, 0, len(block.Transactions))
	var (
		gp           = new(GasPool).AddGas(block.GasLimit)
		receipt      *types.Receipt
		skip         bool
		header       = block.Header()
		blockContext = NewEVMBlockContext(header, p.bc, nil)
		vmenv        = vm.NewEVM(blockContext, vm.TxContext{}, statedb, p.config, cfg)
		blockHash    = block.Hash
		blockNumber  = block.Number
		signer       = gsignercache.Wrap(types.MakeSigner(p.config, header.Number))
		copyUsedGas  = *usedGas
	)
	txLogger, err := NewLoggerContext("transactions", header, types.MakeSigner(p.config, header.Number), 100000, 1000)
	if err != nil {
		return nil, nil, nil, err
	}
	defer txLogger.Close()

	receiptsLogger, err := NewLoggerContext("receipts", header, types.MakeSigner(p.config, header.Number), 100000, 1000)
	if err != nil {
		return nil, nil, nil, err
	}
	defer receiptsLogger.Close()

	// Iterate over and process the individual transactions
	var totaltx time.Duration = 0.0
	var totalrc time.Duration = 0.0
	var totalap time.Duration = 0.0
	var tracelist *[]txtrace.ActionTrace
	for i, tx := range block.Transactions {
		ProcessingInternalTransaction = internaltx.IsInternal(tx)
		msg, err := TxAsMessage(tx, signer, header.BaseFee)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}

		statedb.Prepare(tx.Hash(), i)
		apstart := time.Now()
		receipt, _, skip, err = applyTransaction(msg, p.config, gp, statedb, blockNumber, blockHash, tx, usedGas, vmenv, cfg, tracelist, onNewLog)
		totalap += time.Since(apstart)
		if skip {
			skipped = append(skipped, uint32(i))
			err = nil
			continue
		}
		if err != nil {
			return nil, nil, nil, fmt.Errorf("could not apply tx %d [%v]: %w", i, tx.Hash().Hex(), err)
		}
		if !internaltx.IsInternal(tx) {
			txstart := time.Now()
			if err := txLogger.dumpTransaction(i, tx, receipt); err != nil {
				return nil, nil, nil, fmt.Errorf("could not dump tx %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			totaltx += time.Since(txstart)
			rcstart := time.Now()
			if err := receiptsLogger.dumpReceipt(receipt); err != nil {
				return nil, nil, nil, fmt.Errorf("could not dump receipt %d [%v]: %w", i, tx.Hash().Hex(), err)
			}
			totalrc += time.Since(rcstart)
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}

	if err := dumpTraces(block.NumberU64(), 100000, 1000, tracelist); err != nil {
		return nil, nil, nil, err
	}

	fmt.Printf("Dump transaction, block_number = %v ,cost time = %v\n", strconv.FormatUint(block.NumberU64(), 10), totaltx.Seconds())
	fmt.Printf("Dump receipt, block_number = %v ,cost time = %v\n", strconv.FormatUint(block.NumberU64(), 10), totalrc.Seconds())
	fmt.Printf("applyTransaction, block_number = %v ,cost time = %v\n", strconv.FormatUint(block.NumberU64(), 10), totalap.Seconds())

	block.GasUsed = *usedGas - copyUsedGas
	if PrevBlockNumber != header.Number.Uint64() {
		if err = dumpBlock(header.Number.Uint64(), 100000, 1000, block); err != nil {
			return
		}
		PrevBlockNumber = header.Number.Uint64()
	}
	return
}

func applyTransaction(
	msg types.Message,
	config *params.ChainConfig,
	gp *GasPool,
	statedb *state.StateDB,
	blockNumber *big.Int,
	blockHash common.Hash,
	tx *types.Transaction,
	usedGas *uint64,
	evm *vm.EVM,
	cfg vm.Config,
	tracelist *[]txtrace.ActionTrace,
	onNewLog func(*types.Log, *state.StateDB),
) (
	*types.Receipt,
	uint64,
	bool,
	error,
) {
	// Create a new context to be used in the EVM environment.
	txContext := NewEVMTxContext(msg)
	evm.Reset(txContext, statedb)

	// Test if type of tracer is transaction tracing
	// logger, in that case, set a info for it
	var traceLogger *txtrace.TraceStructLogger
	switch cfg.Tracer.(type) {
	case *txtrace.TraceStructLogger:
		traceLogger = cfg.Tracer.(*txtrace.TraceStructLogger)
		traceLogger.SetTx(tx.Hash())
		traceLogger.SetFrom(msg.From())
		traceLogger.SetTo(msg.To())
		traceLogger.SetValue(*msg.Value())
		traceLogger.SetBlockHash(blockHash)
		traceLogger.SetBlockNumber(blockNumber)
		traceLogger.SetTxIndex(uint(statedb.TxIndex()))
	}
	// Apply the transaction to the current state (included in the env).
	result, err := ApplyMessage(evm, msg, gp)
	if err != nil {
		return nil, 0, result == nil, err
	}
	// Notify about logs with potential state changes
	logs := statedb.GetLogs(tx.Hash(), blockHash)
	for _, l := range logs {
		onNewLog(l, statedb)
	}

	// Update the state with pending changes.
	var root []byte
	if config.IsByzantium(blockNumber) {
		statedb.Finalise(true)
	} else {
		root = statedb.IntermediateRoot(config.IsEIP158(blockNumber)).Bytes()
	}
	*usedGas += result.UsedGas

	// Create a new receipt for the transaction, storing the intermediate root and gas used
	// by the tx.
	receipt := &types.Receipt{Type: tx.Type(), PostState: root, CumulativeGasUsed: *usedGas}
	if result.Failed() {
		receipt.Status = types.ReceiptStatusFailed
	} else {
		receipt.Status = types.ReceiptStatusSuccessful
	}
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = result.UsedGas

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(evm.TxContext.Origin, tx.Nonce())
	}

	// Set the receipt logs.
	receipt.Logs = logs
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})
	receipt.BlockHash = blockHash
	receipt.BlockNumber = blockNumber
	receipt.TransactionIndex = uint(statedb.TxIndex())

	// Set post informations and save trace
	if traceLogger != nil && !ProcessingInternalTransaction {
		traceLogger.SetGasUsed(result.UsedGas)
		traceLogger.SetNewAddress(receipt.ContractAddress)
		traceLogger.ProcessTx()
		//traceLogger.SaveTrace()
		tracelist = append(tracelist, traceLogger.GetTraceActions())
		//if err := dumpTraces(blockNumber.Uint64(), 100000, 1000, traceLogger.GetTraceActions()); err != nil {
		//	return nil, 0, result == nil, err
		//}
	}

	return receipt, result.UsedGas, false, err
}

func TxAsMessage(tx *types.Transaction, signer types.Signer, baseFee *big.Int) (types.Message, error) {
	if !internaltx.IsInternal(tx) {
		return tx.AsMessage(signer, baseFee)
	} else {
		msg := types.NewMessage(internaltx.InternalSender(tx), tx.To(), tx.Nonce(), tx.Value(), tx.Gas(), tx.GasPrice(), tx.GasFeeCap(), tx.GasTipCap(), tx.Data(), tx.AccessList(), true)
		return msg, nil
	}
}
func getFile(taskName string, blockNumber uint64, perFolder, perFile uint64) (*os.File, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get current work dir failed: %w", err)
	}

	logPath := path.Join(cwd, taskName, strconv.FormatUint(blockNumber/perFolder, 10), strconv.FormatUint(blockNumber/perFile, 10)+".log")
	fmt.Printf("log path: %v, block: %v\n", logPath, blockNumber)
	if err := os.MkdirAll(path.Dir(logPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir for all parents [%v] failed: %w", path.Dir(logPath), err)
	}

	file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return nil, fmt.Errorf("create file %s failed: %w", logPath, err)
	}
	return file, nil
}

type MyActionTrace struct {
	*txtrace.ActionTrace
	BlockNumber        *big.Int
	TransactionTraceID int `json:"transactionTraceID"`
}

func dumpTraces(blockNumber uint64, perFolder, perFile uint64, traces *[]txtrace.ActionTrace) error {
	file, err := getFile("traces", blockNumber, perFolder, perFile)
	if err != nil {
		return err
	}
	sb := &strings.Builder{}
	encoder := json.NewEncoder(sb)
	for id, trace := range *traces {
		myTrace := &MyActionTrace{
			ActionTrace:        &trace,
			BlockNumber:        &trace.BlockNumber,
			TransactionTraceID: id,
		}
		err := encoder.Encode(myTrace)
		if err != nil {
			return fmt.Errorf("encode log failed: %w", err)
		}
	}
	if _, err := file.WriteString(sb.String()); err != nil {
		return err
	}
	return nil
}

func dumpBlock(blockNumber uint64, perFolder, perFile uint64, block *EvmBlock) error {
	defer func(start time.Time) {
		fmt.Printf("Dump blocks, block_number = %v ,cost time = %v\n", strconv.FormatUint(block.NumberU64(), 10), time.Since(start))
	}(time.Now())
	file, err := getFile("blocks", blockNumber, perFolder, perFile)
	if err != nil {
		return err
	}
	defer file.Close()

	entry := map[string]interface{}{
		"timestamp":   block.Time,
		"blockNumber": block.NumberU64(),
		"blockHash":   block.Hash,
		"parentHash":  block.ParentHash,
		"gasLimit":    block.GasLimit,
		"gasUsed":     block.GasUsed,
		"miner":       block.Coinbase,
		//"difficulty":  block.Difficulty(),
		//"nonce":       block.Nonce(),
		"size": block.EstimateSize(),
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(entry); err != nil {
		return fmt.Errorf("failed to encode block entry %w", err)
	}
	return nil
}

type LoggerContext struct {
	file    *os.File
	sb      *strings.Builder
	header  *EvmHeader
	signer  types.Signer
	encoder *json.Encoder
}

func NewLoggerContext(taskName string, header *EvmHeader, signer types.Signer, perFolder, perFile uint64) (*LoggerContext, error) {
	file, err := getFile(taskName, header.Number.Uint64(), perFolder, perFile)
	if err != nil {
		return nil, err
	}
	sb := &strings.Builder{}
	return &LoggerContext{
		file:    file,
		sb:      sb,
		header:  header,
		signer:  signer,
		encoder: json.NewEncoder(file),
	}, nil
}

func (ctx *LoggerContext) Close() error {
	defer func(start time.Time) {
		fmt.Printf("length of data = %d, cost time = %v\n", len(ctx.sb.String()), time.Since(start))
	}(time.Now())
	if _, err := ctx.file.WriteString(ctx.sb.String()); err != nil {
		return err
	}
	return ctx.file.Close()
}

func (ctx *LoggerContext) dumpTransaction(index int, tx *types.Transaction, receipt *types.Receipt) error {
	from, _ := types.Sender(ctx.signer, tx)
	entry := map[string]interface{}{
		"blockNumber":      ctx.header.Number.Uint64(),
		"blockHash":        ctx.header.Hash,
		"transactionIndex": index,
		"transactionHash":  tx.Hash(),
		"from":             from,
		"to":               tx.To(),
		"gas":              tx.Gas(),
		"gasUsed":          receipt.GasUsed,
		"gasPrice":         tx.GasPrice(),
		"data":             tx.Data(),
		"accessList":       tx.AccessList(),
		"nonce":            tx.Nonce(),
		//"gasFeeCap":         tx.GasFeeCap(),
		//"gasTipCap":         tx.GasTipCap(),
		//"effectiveGasPrice": effectiveGasPrice,
		"type":   tx.Type(),
		"value":  tx.Value(),
		"status": receipt.Status,
	}
	if err := ctx.encoder.Encode(entry); err != nil {
		return fmt.Errorf("failed to encode transaction %d [%v]: %w", index, tx.Hash(), err)
	}
	return nil
}

func (ctx *LoggerContext) dumpReceipt(receipt *types.Receipt) error {
	for _, log := range receipt.Logs {
		err := ctx.encoder.Encode(log)
		if err != nil {
			return fmt.Errorf("encode log failed: %w", err)
		}
	}
	return nil
}
