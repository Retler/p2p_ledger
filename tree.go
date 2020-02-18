package main

import (
	"math/big"
	"encoding/gob"
	"bytes"
	"fmt"
	"sort"
)


type Node struct{
	Slot       int
	Draw       []byte
	BlockData  BlockData
	ParentHash [32]byte
	Children   [][32]byte
	Creator    string // ip:portnumber
	Signature  []byte
}

type BlockData struct {
	Seed int
	Hardness []byte
	Transactions []SignedTransaction
	Delivered bool
}

type Tree struct{
	Genesis *Node
	Blocks map[[32]byte]*Node
	BestPathAtLastTransaction BestPathResult // A reference to the previous best path so we can compute rollbacks (if any)
	CurrentBestPathLength int
	LeftmostPathLength int
}

func MakeFreshTree() Tree{
	blocks := make(map[[32]byte]*Node)
	genesis := &Node{0,[]byte{},BlockData{12345, computeHardness(), []SignedTransaction{},true},[32]byte{},[][32]byte{},"",[]byte{}}
	blocks[genesis.GenerateNodeHash()] = genesis
	tree := Tree{genesis, blocks, BestPathResult{},0,0}

	return tree
}

func DeliveredTransactionsInPath(nodes []*Node) map[string]SignedTransaction {
	result := make(map[string]SignedTransaction, 0)

	for _,v := range nodes{
		if (v.BlockData.Delivered){ // Only add transactions that are already delivered
			for _,v2 := range v.BlockData.Transactions{
				result[v2.ID] = v2
			}
		}
	}

	return result
}

func MakeBlock(slot int, draw big.Int, transactions []SignedTransaction, parenthash [32]byte, creator string) *Node{
	block := Node{slot, draw.Bytes(),BlockData{0,[]byte{},transactions,false}, parenthash, [][32]byte{},creator,[]byte{}}
	sig := Sign(*new(big.Int).SetBytes(block.toBytes()))
	block.Signature = sig.Bytes()

	return &block
}

func MakeFakeBlock(slot int, draw big.Int, transactions []SignedTransaction, parenthash [32]byte, creator string) *Node{
	block := Node{slot, draw.Bytes(),BlockData{0,[]byte{},transactions,false}, parenthash, [][32]byte{},creator,[]byte{}}

	return &block
}

func (n *Node) GenerateNodeHash() [32]byte{
	slot := new(big.Int).SetInt64(int64(n.Slot))
	phash := new(big.Int).SetBytes(n.ParentHash[:])
	creator := new(big.Int).SetBytes([]byte(n.Creator))

	bytes := make([]byte, 0)
	bytes = append(bytes, slot.Bytes()...)
	bytes = append(bytes, n.Draw...)
	bytes = append(bytes, phash.Bytes()...)
	bytes = append(bytes, creator.Bytes()...)

	result := Sha256Hash(bytes)

	return result
}

func (t *Tree) AllUndeliveredeTransactionsInBestPath() []SignedTransaction{
	result := make([]SignedTransaction, 0)
	for _,v := range t.BestPath(tree.Genesis).path{
		if(!v.BlockData.Delivered){
			result = append(result, v.BlockData.Transactions...)
		}
	}
	return result
}

func (t *Tree) AddNode(node *Node){
	nodeHash := node.GenerateNodeHash()
	t.Blocks[nodeHash] = node
	parent := t.Blocks[node.ParentHash] // TODO: Maybe the parrent has not arrived yet??
	parent.AddChild(nodeHash)
}

func (n *Node) AddChild(nodeHash [32]byte){
	n.Children = append(n.Children, nodeHash)
}

func (n *Node) toBytes() []byte{
	var node bytes.Buffer
	enc := gob.NewEncoder(&node)
	node1 := Node{n.Slot,n.Draw,n.BlockData,n.ParentHash,n.Children,n.Creator,[]byte{}}
	enc.Encode(&node1)

	return node.Bytes()
}

type BestPathResult struct {
	pathLength int
	path []*Node
}

func (t *Tree) BestPath(startNode *Node) BestPathResult{
	if(len(startNode.Children) == 0){ // You are a leaf
		return BestPathResult{1, []*Node{startNode}}
	}else{ // You are a node
		bestPathOfChildren := make([]BestPathResult, 0)

		for _,v := range startNode.Children{
			child := t.Blocks[v]
			bestPathOfChild := t.BestPath(child)
			bestPathOfChildren = append(bestPathOfChildren, bestPathOfChild)
		}

		theBestPathOfChildren := maxPathOfChildren(bestPathOfChildren)
		return BestPathResult{theBestPathOfChildren.pathLength+1,append(theBestPathOfChildren.path,startNode)}
	}
}


func maxPathOfChildren(results []BestPathResult) BestPathResult {
	bestPathValue := 0
	firstIteration := make([]BestPathResult, 0)

	// First we sort out by path length
	for _,v := range results{
		if(v.pathLength > bestPathValue){
			bestPathValue = v.pathLength
			firstIteration = []BestPathResult{} // We empty the array
			firstIteration = append(firstIteration, v)
		}else if(v.pathLength == bestPathValue){
			firstIteration = append(firstIteration, v)
		}
	}

	bestLeafSoFar := new(big.Int).SetInt64(0)
	bestPathResult := BestPathResult{}
	// Then we sort out by leaf value (if there are more than one left). The value of the leaf is in this case just the draw of the block.
	if(len(firstIteration) > 1){
		for _,v := range firstIteration {
			bestLeafOfPath := v.path[len(v.path)-1]
			if (new(big.Int).SetBytes(bestLeafOfPath.Draw).Cmp(bestLeafSoFar) == 1) { // If bestLeaf > bestLeafSoFar. We dont expect to be collisions here...
				bestLeafSoFar = new(big.Int).SetBytes(bestLeafOfPath.Draw)
				bestPathResult = v
			}
		}
		return bestPathResult
	}else{
		return firstIteration[0]
	}
}

func (t *Tree)BestLeaf() Node{
	bestPathResult := t.BestPath(tree.Genesis)
	bestLeaf := bestPathResult.path[0] // The last element in the list must be best leaf

	return *bestLeaf
}


func (t *Tree) MakeTransactions(){
	currentBestPath := NodeSliceToMap(t.BestPath(t.Genesis).path)
	oldBestPath := NodeSliceToMap(t.BestPathAtLastTransaction.path)

	nodesToRollBack := NodeSetMinus(oldBestPath, currentBestPath)
	nodesToDo := NodeSetMinus(currentBestPath, oldBestPath)

	doRollback(nodesToRollBack)
	doRollforward(nodesToDo)
}

type bySlot []*Node

func (n bySlot) Len() int{
	return len(n)
}

func (n bySlot) Swap(i,j int) {
	n[i], n[j] = n[j], n[i]
}

func (n bySlot) Less(i,j int)bool{
	return n[i].Slot < n[j].Slot
}

func doRollforward(nodes []*Node) {

	sort.Sort(bySlot(nodes))

	// Make all undelivered transactions on the best path
	for _,v := range nodes{
		if(!v.BlockData.Delivered){
			for _,v2 := range v.BlockData.Transactions{
				ledger.SignedTransaction(&v2)
				v.BlockData.Delivered = true
			}

		}
	}
}

func reverse(nodes []*Node) []*Node{
	for i := 0; i < len(nodes)/2; i++ {
		j := len(nodes) - i - 1
		ival := nodes[i]
		jval := nodes[j]
		nodes[i] = jval
		nodes[j] = ival
	}
	return nodes
}

func doRollback(nodes []*Node) {
	// Rollback all transactions on this path starting from the highest slot to the lowest.
	sort.Sort(bySlot(nodes))
	reverse(nodes) // Reverse because we do rollback from the highest slot first

	for _,v := range nodes{
		fmt.Println("Making rollback of slot ", v.Slot)
		fmt.Println("This slot is: " , v.Slot,  "Number of transactions in this block is: ", len(v.BlockData.Transactions))
		if(v.BlockData.Delivered){
			for _,v2 := range reverseTransactions(v.BlockData.Transactions){ // Reverse the order of transactions in block
				ledger.RevertTransaction(&v2)
				v.BlockData.Delivered = false
				unhandledTransactions[v2.ID] = v2 // Put the transaction back in the unhandled transactions queue
			}

		}
	}
}
func reverseTransactions(transactions []SignedTransaction) []SignedTransaction{
	for i := 0; i < len(transactions)/2; i++ {
		j := len(transactions) - i - 1
		transactions[i], transactions[j] = transactions[j], transactions[i]
	}
	return transactions
}
func NodeSliceToMap(nodes []*Node) map[[32]byte]*Node {
	result := make(map[[32]byte]*Node)

	for _,v := range nodes{
		result[v.GenerateNodeHash()] = v
	}
	return result
}

func (t *Tree) Size() int{
	return len(t.Blocks)
}
func (t *Tree) LeftmostLeaf() Node {
	leftMostLeaf := getFirstChildRecursive(t.Genesis)
	return *leftMostLeaf
}

func (t *Tree) LeftMostPathLength() int{
	return getLeftPathLengthRecursive(tree.Genesis)
}

func CreateSmallTree(){ // Creates a splitted tree where the right path is longest for testing malicious peer
	dummyBlock1 := MakeFakeBlock(0,*dummyBigint,[]SignedTransaction{},tree.Genesis.GenerateNodeHash(),"one")
	dummyBlock2 := MakeFakeBlock(0,*dummyBigint,[]SignedTransaction{},tree.Genesis.GenerateNodeHash(),"two")
	dummyBlock3 := MakeFakeBlock(0,*dummyBigint,[]SignedTransaction{},dummyBlock2.GenerateNodeHash(),"tree")
	tree.AddNode(dummyBlock1)
	tree.AddNode(dummyBlock2)
	tree.AddNode(dummyBlock3)

}

func getLeftPathLengthRecursive(n *Node) int{
	if(len(n.Children) > 0){
		leftChild := tree.Blocks[n.Children[0]]
		return 1 + getLeftPathLengthRecursive(leftChild)
	}else{ // Arrived at leaf
		return 1
	}
}

func getFirstChildRecursive(n *Node) *Node{
	if(len(n.Children) > 0){
		return getFirstChildRecursive(tree.Blocks[n.Children[0]])
	}else{
		return n //This is the leftmost leaf of the tree
	}
}

func NodeSetMinus(path1 map[[32]byte]*Node, path2 map[[32]byte]*Node) []*Node{
	result := make([]*Node, 0)

	for k,v := range path1{
		if _, exists := path2[k]; !exists { // The unhandled transaction doesn't exist in current handled transaction path
			result = append(result, v)
		}
	}

	return result
}

func TransactionSetMinus(unhandledTransactions map[string]SignedTransaction, handledTransactionsInPath map[string]SignedTransaction) []SignedTransaction {
	result := make([]SignedTransaction, 0)

	for k,v := range unhandledTransactions{
		if _, exists := handledTransactionsInPath[k]; !exists { // The unhandled transaction doesn't exist in current handled transaction path
			result = append(result, v)
		}
	}

	return result
}

func computeHardness() []byte{ // hardness = (256bit * 10^6)*0,99
	full256 := full256bitNumber()
	multiplier := new(big.Int).SetInt64(9000000)
	hardness1 := new(big.Int).Mul(full256, multiplier)
	hardness2 := new(big.Int).Div(hardness1, new(big.Int).SetInt64(100))
	hardness3 := new(big.Int).Sub(hardness1, hardness2)

	return hardness3.Bytes()
}

func full256bitNumber() *big.Int{
	bytes := []byte{255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255}
	return new(big.Int).SetBytes(bytes)
}