package dfs

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/util"
)

func TestDFSAddInstructionReachNextBB(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(10)
	b2 := d.AddBasicBlock(0)
	require.Len(t, d.blocks, 2)
	assert.EqualValues(t, 1, b1.index)
	assert.EqualValues(t, 0, b2.index)
	err := d.AddInstruction(b2, 10, true)
	require.NoError(t, err)
	assert.True(t, b2.Explored())
	assert.NotNil(t, b2.findEdge(b1))
}

func TestDFSAddInstructionReachNextBBOverlaps(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(10)
	b2 := d.AddBasicBlock(0)
	require.Len(t, d.blocks, 2)
	assert.EqualValues(t, 1, b1.index)
	assert.EqualValues(t, 0, b2.index)
	err := d.AddInstruction(b2, 11, true)
	require.Error(t, err)
}

func TestDFSAddBBMatchStart(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(10)
	b2 := d.AddBasicBlock(10)
	assert.Equal(t, b1, b2)
}

func TestDFSAddBBNoMatchInsert(t *testing.T) {
	d := DFS{}
	_ = d.AddBasicBlock(10)
	_ = d.AddBasicBlock(100)
	_ = d.AddBasicBlock(50)
	require.Len(t, d.blocks, 3)
}

func TestDFSAddBBSplitExplored(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0)
	err := d.AddInstruction(b1, 10, true)
	require.NoError(t, err)
	b1.MarkExplored()
	b2 := d.AddBasicBlock(5)
	assert.True(t, b2.Explored())
	assert.True(t, b1.Explored())
	assert.NotEqual(t, b1, b2)
	assert.EqualValues(t, 0, b1.start)
	assert.EqualValues(t, 5, b1.end)
	assert.EqualValues(t, 5, b2.start)
	assert.EqualValues(t, 10, b2.end)
	assert.NotNil(t, b1.findEdge(b2))

	assert.Len(t, d.blocks, 2)
}

func TestDFSAddBBSplitExploredNonLast(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0)
	_ = d.AddBasicBlock(100)
	err := d.AddInstruction(b1, 10, true)
	require.NoError(t, err)
	b1.MarkExplored()
	b2 := d.AddBasicBlock(5)
	assert.True(t, b2.Explored())
	assert.True(t, b1.Explored())
	assert.NotEqual(t, b1, b2)
	assert.EqualValues(t, 0, b1.start)
	assert.EqualValues(t, 5, b1.end)
	assert.EqualValues(t, 5, b2.start)
	assert.EqualValues(t, 10, b2.end)
	assert.NotNil(t, b1.findEdge(b2), b2)
	assert.Len(t, d.blocks, 3)
}

func TestDFSAddBBSplitUnexplored(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0)
	err := d.AddInstruction(b1, 10, true)
	require.NoError(t, err)
	b2 := d.AddBasicBlock(5)
	assert.False(t, b2.Explored())
	assert.True(t, b1.Explored())
	assert.NotEqual(t, b1, b2)
	assert.EqualValues(t, 0, b1.start)
	assert.EqualValues(t, 5, b1.end)
	assert.EqualValues(t, 5, b2.start)
	assert.EqualValues(t, 10, b2.end)
	assert.NotNil(t, b1.findEdge(b2))
	assert.Len(t, d.blocks, 2)
}

func TestRanges(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0x10C59D)
	_ = d.AddInstruction(b1, 5, false)
	b2 := d.AddBasicBlock(0x10C5A8)
	_ = d.AddInstruction(b2, 3, true)
	ranges := d.Ranges()
	require.EqualValues(t, []util.Range{{Start: 0x10C59D, End: 0x10C5A8 + 3}}, ranges)
}

func TestAddBBSplitEdges(t *testing.T) {
	d := DFS{}
	b1 := d.AddBasicBlock(0)
	b2 := d.AddBasicBlock(100)
	b3 := d.AddBasicBlock(200)
	err := d.AddInstruction(b1, 100, true)
	d.AddEdge(b1, b3, EdgeTypeJump)
	require.NoError(t, err)

	e1 := b1.findEdge(b2)
	require.NotNil(t, e1)
	require.Equal(t, EdgeTypeFallThrough, e1.typ)

	e2 := b1.findEdge(b3)
	require.NotNil(t, e2)
	require.Equal(t, EdgeTypeJump, e2.typ)

	b1mid := d.AddBasicBlock(50)

	e1 = b1mid.findEdge(b2)
	require.NotNil(t, e1)
	require.Equal(t, EdgeTypeFallThrough, e1.typ)

	e2 = b1mid.findEdge(b3)
	require.NotNil(t, e2)
	require.Equal(t, EdgeTypeJump, e2.typ)

	e1 = b1.findEdge(b2)
	require.Nil(t, e1)

	e2 = b1.findEdge(b3)
	require.Nil(t, e2)

	e3 := b1.findEdge(b1mid)
	require.NotNil(t, e3)
	require.Equal(t, EdgeTypeFallThrough, e3.typ)
}
