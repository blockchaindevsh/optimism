package script

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum-optimism/optimism/op-chain-ops/foundry"
	"github.com/ethereum-optimism/optimism/op-service/testlog"
)

//go:generate ./testdata/generate.sh

func TestScript(t *testing.T) {
	logger, captLog := testlog.CaptureLogger(t, log.LevelInfo)
	af := foundry.OpenArtifactsDir("./testdata/test-artifacts")

	scriptContext := DefaultContext
	h := NewHost(logger, af, nil, scriptContext)
	addr, err := h.LoadContract("ScriptExample.s.sol", "ScriptExample")
	require.NoError(t, err)

	require.NoError(t, h.EnableCheats())

	h.SetEnvVar("EXAMPLE_BOOL", "true")
	input := bytes4("run()")
	returnData, _, err := h.Call(scriptContext.Sender, addr, input[:], DefaultFoundryGasLimit, uint256.NewInt(0))
	require.NoError(t, err, "call failed: %x", string(returnData))
	require.NotNil(t, captLog.FindLog(testlog.NewMessageFilter("sender nonce 1")))

	require.NoError(t, h.cheatcodes.Precompile.DumpState("noop"))
	// and a second time, to see if we can revisit the host state.
	require.NoError(t, h.cheatcodes.Precompile.DumpState("noop"))
}

func TestModBalance(t *testing.T) {
	logger, _ := testlog.CaptureLogger(t, log.LevelInfo)
	af := foundry.OpenArtifactsDir("./testdata/test-artifacts")

	scriptContext := DefaultContext
	h := NewHost(logger, af, nil, scriptContext)
	addr, err := h.LoadContract("ScriptExample.s.sol", "ScriptExample")
	require.NoError(t, err)

	require.NoError(t, h.EnableCheats())

	artifact, err := h.af.ReadArtifact("ScriptExample.s.sol", "ScriptExample")
	require.NoError(t, err)
	account := common.Address{1, 2}

	balance, err := readBalance(t, h, artifact, scriptContext, addr, account)
	require.NoError(t, err)
	// for testing decoding is correct
	// require.True(t, balance.Cmp(big.NewInt(1)) == 0)
	require.True(t, balance.Cmp(big.NewInt(0)) == 0)

	slot := targetSlot(account, 1)

	bitSize := 256
	targetValue, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), uint(bitSize)))
	require.NoError(t, err)
	bytes32 := uint256.MustFromBig(targetValue).Bytes32()
	h.cheatcodes.Precompile.Store(addr, slot, bytes32)

	balance, err = readBalance(t, h, artifact, scriptContext, addr, account)
	require.NoError(t, err)
	require.True(t, balance.Cmp(targetValue) == 0, "got %v, expect %v", balance, targetValue)
}

func targetSlot(account common.Address, balancesSlot uint64) (slot common.Hash) {
	Uint64, _ := abi.NewType("uint64", "", nil)
	Address, _ := abi.NewType("address", "", nil)
	args := abi.Arguments{{Name: "addr", Type: Address, Indexed: false}, {Name: "slot", Type: Uint64, Indexed: false}}
	data, _ := args.Pack(account, balancesSlot)
	slot = crypto.Keccak256Hash(data)
	return
}

func readBalanceFromState(h *Host, addr, account common.Address) (returnValue *big.Int) {
	state := h.state.GetState(addr, targetSlot(account, 1))
	returnValue = new(big.Int)
	returnValue.SetBytes(state[:])
	return
}

func readBalance(t *testing.T, h *Host, artifact *foundry.Artifact, scriptContext Context, addr, account common.Address) (returnValue *big.Int, err error) {
	method := artifact.ABI.Methods["balanceOf"]
	input, err := artifact.ABI.Pack("balanceOf", account)
	if err != nil {
		return
	}
	returnData, _, err := h.Call(scriptContext.Sender, addr, input[:], DefaultFoundryGasLimit, uint256.NewInt(0))
	if err != nil {
		return
	}
	returnValueInterface, err := artifact.ABI.Unpack("balanceOf", returnData)
	if err != nil {
		return
	}
	returnValue = new(big.Int)
	err = method.Outputs.Copy(&returnValue, returnValueInterface)
	if err != nil {
		return
	}

	valueFromState := readBalanceFromState(h, addr, account)
	require.True(t, valueFromState.Cmp(returnValue) == 0, "call value:%v, state value:%v", returnValue, valueFromState)
	return
}
func TestScriptBroadcast(t *testing.T) {
	logger := testlog.Logger(t, log.LevelDebug)
	af := foundry.OpenArtifactsDir("./testdata/test-artifacts")

	mustEncodeCalldata := func(method, input string) []byte {
		packer, err := abi.JSON(strings.NewReader(fmt.Sprintf(`[{"type":"function","name":"%s","inputs":[{"type":"string","name":"input"}]}]`, method)))
		require.NoError(t, err)

		data, err := packer.Pack(method, input)
		require.NoError(t, err)
		return data
	}

	fooBar, err := af.ReadArtifact("ScriptExample.s.sol", "FooBar")
	require.NoError(t, err)

	expectedInitCode := bytes.Clone(fooBar.Bytecode.Object)
	// Add the contract init argument we use in the script
	expectedInitCode = append(expectedInitCode, leftPad32(big.NewInt(1234).Bytes())...)
	salt := uint256.NewInt(42).Bytes32()

	senderAddr := common.HexToAddress("0x0000000000000000000000000000000000Badc0d")
	scriptAddr := common.HexToAddress("0x5b73c5498c1e3b4dba84de0f1833c4a029d90519")
	coffeeAddr := common.HexToAddress("0x0000000000000000000000000000000000C0FFEE")
	cafeAddr := common.HexToAddress("0xcafe")
	expBroadcasts := []Broadcast{
		{
			From:    scriptAddr,
			To:      scriptAddr,
			Input:   mustEncodeCalldata("call1", "single_call1"),
			Value:   (*hexutil.U256)(uint256.NewInt(0)),
			GasUsed: 23421,
			Type:    BroadcastCall,
			Nonce:   1, // first action by script (script already has a nonce of 1)
		},
		{
			From:    coffeeAddr,
			To:      scriptAddr,
			Input:   mustEncodeCalldata("call1", "startstop_call1"),
			Value:   (*hexutil.U256)(uint256.NewInt(0)),
			GasUsed: 1521,
			Type:    BroadcastCall,
			Nonce:   0, // first action by 0xc0ffee
		},
		{
			From:    coffeeAddr,
			To:      scriptAddr,
			Input:   mustEncodeCalldata("call2", "startstop_call2"),
			Value:   (*hexutil.U256)(uint256.NewInt(0)),
			GasUsed: 1565,
			Type:    BroadcastCall,
			Nonce:   1, // second action of 0xc0ffee
		},
		{
			From:    common.HexToAddress("0x1234"),
			To:      scriptAddr,
			Input:   mustEncodeCalldata("nested1", "nested"),
			Value:   (*hexutil.U256)(uint256.NewInt(0)),
			GasUsed: 2763,
			Type:    BroadcastCall,
			Nonce:   0, // first action of 0x1234
		},
		{
			From:    common.HexToAddress("0x123456"),
			To:      crypto.CreateAddress(common.HexToAddress("0x123456"), 0),
			Input:   expectedInitCode,
			Value:   (*hexutil.U256)(uint256.NewInt(0)),
			GasUsed: 39112,
			Type:    BroadcastCreate,
			Nonce:   0, // first action of 0x123456
		},
		{
			From:    DeterministicDeployerAddress,
			To:      crypto.CreateAddress2(DeterministicDeployerAddress, salt, crypto.Keccak256(expectedInitCode)),
			Input:   expectedInitCode,
			Value:   (*hexutil.U256)(uint256.NewInt(0)),
			Type:    BroadcastCreate2,
			GasUsed: 39112,
			Salt:    salt,
			Nonce:   0, // first action of 0xcafe
		},
		{
			From:    scriptAddr,
			To:      crypto.CreateAddress(scriptAddr, 2),
			Input:   expectedInitCode,
			Value:   (*hexutil.U256)(uint256.NewInt(0)),
			GasUsed: 39112,
			Type:    BroadcastCreate,
			Nonce:   2, // second action, on top of starting at 1.
		},
	}

	var broadcasts []Broadcast
	hook := func(broadcast Broadcast) {
		broadcasts = append(broadcasts, broadcast)
	}
	h := NewHost(logger, af, nil, DefaultContext, WithBroadcastHook(hook), WithCreate2Deployer())
	addr, err := h.LoadContract("ScriptExample.s.sol", "ScriptExample")
	require.NoError(t, err)

	require.NoError(t, h.EnableCheats())

	input := bytes4("runBroadcast()")
	returnData, _, err := h.Call(senderAddr, addr, input[:], DefaultFoundryGasLimit, uint256.NewInt(0))
	require.NoError(t, err, "call failed: %x", string(returnData))

	expected, err := json.MarshalIndent(expBroadcasts, "  ", "  ")
	require.NoError(t, err)
	got, err := json.MarshalIndent(broadcasts, "  ", "  ")
	require.NoError(t, err)
	require.Equal(t, string(expected), string(got))

	// Assert that the nonces for accounts participating in the
	// broadcast increase. The scriptAddr check is set to 3 to
	// account for the initial deployment of the contract and
	// two additional calls.
	require.EqualValues(t, 0, h.GetNonce(senderAddr))
	require.EqualValues(t, 3, h.GetNonce(scriptAddr))
	require.EqualValues(t, 2, h.GetNonce(coffeeAddr))
	// This is one because we still need to bump the nonce of the
	// address that will perform the send to the Create2Deployer.
	require.EqualValues(t, 1, h.GetNonce(cafeAddr))
}
