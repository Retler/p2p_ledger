package main

import (
	"testing"
	"math/big"
	"fmt"
	"time"
	"log"
)

func TestBestPathBasic(t *testing.T) {

	tree := MakeFreshTree()
	bestPath := tree.BestPath(tree.Genesis)

	if bestPath.pathLength != 1 || len(bestPath.path) != 1 {
		t.Error("Best path length is incorrect! Should be 1 but is ", bestPath.pathLength)
	}
}

func TestBestPathShouldBe3(t *testing.T){
	tree := MakeFreshTree()
	draw1 := new(big.Int).SetInt64(5)
	draw2 := new(big.Int).SetInt64(8)
	node1 := MakeBlock(1, *draw1,[]SignedTransaction{},tree.Genesis.GenerateNodeHash(),"")
	node2 := MakeBlock(2, *draw2, []SignedTransaction{}, node1.GenerateNodeHash(),"")
	tree.AddNode(node1)
	tree.AddNode(node2)

	fmt.Println("Genesis has ", len(tree.Genesis.Children), " child(ren)")
	fmt.Println("Node1 has ", len(tree.Blocks[node1.GenerateNodeHash()].Children), " child(ren)")
	fmt.Println("Node2 has ", len(node2.Children), " child(ren)")

	fmt.Println("Tree size is: ", len(tree.Blocks))


	bestPath := tree.BestPath(tree.Genesis) // Best path from genesis. Because of recusrion, we need to provide starting node.

	fmt.Println("Best path length value is: ", bestPath.pathLength)
	fmt.Println("Best path length is: ", len(bestPath.path))


	if bestPath.pathLength != 3 || len(bestPath.path) != 3 {
		t.Error("Best path length is incorrect! Should be 3 but is ", bestPath.pathLength)
	}
}

func TestBestPathOfTwoPossibleShouldBe4(t *testing.T){
	tree := MakeFreshTree()
	draw1 := new(big.Int).SetInt64(5)
	draw2 := new(big.Int).SetInt64(8)
	draw3 := new(big.Int).SetInt64(10)
	draw4 := new(big.Int).SetInt64(12)
	draw5 := new(big.Int).SetInt64(16)
	node1 := MakeBlock(1, *draw1,[]SignedTransaction{},tree.Genesis.GenerateNodeHash(),"")
	node2 := MakeBlock(2, *draw2, []SignedTransaction{}, node1.GenerateNodeHash(),"")
	node3 := MakeBlock(3, *draw3, []SignedTransaction{}, node2.GenerateNodeHash(),"")
	node1_1 := MakeBlock(1, *draw4,[]SignedTransaction{},tree.Genesis.GenerateNodeHash(),"")
	node2_1 := MakeBlock(2, *draw5, []SignedTransaction{}, node1_1.GenerateNodeHash(),"")

	tree.AddNode(node1)
	tree.AddNode(node2)
	tree.AddNode(node3)
	tree.AddNode(node1_1)
	tree.AddNode(node2_1)

	fmt.Println("Node.toBytes node1 is: ", Sha256Hash(node1.toBytes()))
	fmt.Println("Node.toBytes node2 is: ", Sha256Hash(node2.toBytes()))
	fmt.Println("Node.toBytes node3 is: ", Sha256Hash(node3.toBytes()))
	fmt.Println("Node.toBytes node1_1 is: ", Sha256Hash(node1_1.toBytes()))
	fmt.Println("Node.toBytes node2_1 is: ", Sha256Hash(node2_1.toBytes()))

	fmt.Println("Tree size is: ", len(tree.Blocks))

	bestPath := tree.BestPath(tree.Genesis) // Best path from genesis. Because of recusrion, we need to provide starting node.

	fmt.Println("Best path length value is: ", bestPath.pathLength)
	fmt.Println("Best path length is: ", len(bestPath.path))

	if bestPath.pathLength != 4 || len(bestPath.path) != 4 {
		t.Error("Best path length is incorrect! Should be 4 but is ", bestPath.pathLength)
	}
}

func TestTransactionSetMinus(t *testing.T) {
	fmt.Println("Testing TransactionSetMinus")
	unhandledTransactions := make(map[string]SignedTransaction)
	transactionsAlreadyInTree := make(map[string]SignedTransaction)

	mockTransaction1 := MockTransactionObject()
	mockTransaction2 := MockTransactionObject()
	mockTransaction3 := MockTransactionObject()
	mockTransaction4 := MockTransactionObject()
	mockTransaction5 := MockTransactionObject()

	// Add all transactions to unhandled
	unhandledTransactions[mockTransaction1.ID] = mockTransaction1
	unhandledTransactions[mockTransaction2.ID] = mockTransaction2
	unhandledTransactions[mockTransaction3.ID] = mockTransaction3
	unhandledTransactions[mockTransaction4.ID] = mockTransaction4
	unhandledTransactions[mockTransaction5.ID] = mockTransaction5

	if(len(unhandledTransactions) != 5){
		t.Errorf("Error! Unhandled transactions length should be 5 but is %d", len(unhandledTransactions))
	}

	// Add some transactions to the transactions that are in the block
	transactionsAlreadyInTree[mockTransaction1.ID] = mockTransaction1
	transactionsAlreadyInTree[mockTransaction2.ID] = mockTransaction2
	transactionsAlreadyInTree[mockTransaction3.ID] = mockTransaction3

	result := TransactionSetMinus(unhandledTransactions, transactionsAlreadyInTree)

	if(len(result) != 2){
		t.Errorf("Wrong ammount of transactions in result.")
	}else{
		fmt.Println("result length was 2")
	}

	for k,v := range result{
		fmt.Print("result ", k, " is ", v)
	}
}

func TestNodeSetMinus(t *testing.T) {
	fmt.Println("Testing NodeSetMinus")
	nodes1 := make(map[[32]byte]*Node)
	nodes2 := make(map[[32]byte]*Node)

	mockNode1 := MockNodeObject()
	mockNode2 := MockNodeObject()
	mockNode3 := MockNodeObject()
	mockNode4 := MockNodeObject()
	mockNode5 := MockNodeObject()

	// Add all transactions to unhandled
	nodes1[mockNode1.GenerateNodeHash()] = mockNode1
	nodes1[mockNode2.GenerateNodeHash()] = mockNode2
	nodes1[mockNode3.GenerateNodeHash()] = mockNode3
	nodes1[mockNode4.GenerateNodeHash()] = mockNode4
	nodes1[mockNode5.GenerateNodeHash()] = mockNode5

	if(len(nodes1) != 5){
		t.Errorf("Error! node1 length should be 5 but is %d", len(nodes1))
	}

	// Add some transactions to the transactions that are in the block
	nodes2[mockNode1.GenerateNodeHash()] = mockNode1
	nodes2[mockNode2.GenerateNodeHash()] = mockNode2
	nodes2[mockNode3.GenerateNodeHash()] = mockNode3

	result := NodeSetMinus(nodes1, nodes2)

	if(len(result) != 2){
		t.Errorf("Wrong ammount of nodes in result.")
	}else{
		fmt.Println("result length was 2")
	}

	for k,v := range result{
		fmt.Print("result ", k, " is ", v)
	}
}

func TestReverse(t *testing.T) {
	fmt.Println("Testing TestReverse")
	nodes1 := make([]*Node,0)

	mockNode1 := MockNodeObject()
	mockNode2 := MockNodeObject()
	mockNode3 := MockNodeObject()
	mockNode4 := MockNodeObject()
	mockNode5 := MockNodeObject()

	nodes1 = append(nodes1, mockNode1)
	nodes1 = append(nodes1, mockNode2)
	nodes1 = append(nodes1, mockNode3)
	nodes1 = append(nodes1, mockNode4)
	nodes1 = append(nodes1, mockNode5)

	nodes1 = reverse(nodes1)

	testPassed := (nodes1[0]==mockNode5 && nodes1[1]==mockNode4 && nodes1[2]==mockNode3 && nodes1[3]==mockNode2 && nodes1[4]==mockNode1)

	if(!testPassed){
		t.Errorf("Test reverse failed. Result of the reverse function is %v", nodes1)
	}

	transactions := make([]SignedTransaction,0)

	trans1 := MockTransactionObject()
	trans2 := MockTransactionObject()
	trans3 := MockTransactionObject()
	trans4 := MockTransactionObject()
	trans5 := MockTransactionObject()

	transactions = append(transactions, trans1)
	transactions = append(transactions, trans2)
	transactions = append(transactions, trans3)
	transactions = append(transactions, trans4)
	transactions = append(transactions, trans5)

	transactions = reverseTransactions(transactions)

	testPassed = (transactions[0].ID==trans5.ID && transactions[1].ID==trans4.ID && transactions[2].ID==trans3.ID && transactions[3].ID==trans2.ID && transactions[4].ID==trans1.ID)

	if(!testPassed){
		t.Errorf("Test reverse failed. Result of the reverse function is %v", transactions)
	}
}

func TestSpeedOfTransaction(t *testing.T){
	MakePublicPrivateRsaKeys(1000)

	start := time.Now()

	for i := 0; i < 5000; i++{
		// Making a transaction, signing it, and veryfying it:
		transaction := &SignedTransaction{}
		transactionAsBigInt := TransactionAsBigint(transaction)
		hashOfTransaction := Sha256Hash(transactionAsBigInt.Bytes())
		hashOfTransaction = Sha256Hash(transactionAsBigInt.Bytes()) // Hash has to be recomputed at veryfication step
		hashAsBigInt := new(big.Int).SetBytes(hashOfTransaction[:]);
		signature := new(big.Int).Exp(hashAsBigInt, &d,&n)
		Encrypt(*signature, n)
	}

	elapsed := time.Since(start)
	log.Printf("A trasaction took took %s", elapsed/5000)

	//TODO: 1. measure the speed of a transaction 2. measure the speed of tree.BestPath 3. calculate ammount of transactions that can be made in 10 seconds 4. add that to speed of bestpathx2 5. divide that by 10 and get the result
}

func TestSpeedOfBestPath(t *testing.T){
	MakePublicPrivateRsaKeys(1000)

	start := time.Now()

	for i := 0; i < 5000; i++{
		// Making a transaction, signing it, and veryfying it:
		transaction := &SignedTransaction{}
		transactionAsBigInt := TransactionAsBigint(transaction)
		hashOfTransaction := Sha256Hash(transactionAsBigInt.Bytes())
		hashOfTransaction = Sha256Hash(transactionAsBigInt.Bytes()) // Hash has to be recomputed at veryfication step
		hashAsBigInt := new(big.Int).SetBytes(hashOfTransaction[:]);
		signature := new(big.Int).Exp(hashAsBigInt, &d,&n)
		Encrypt(*signature, n)
	}

	elapsed := time.Since(start)
	log.Printf("A trasaction took took %d", elapsed/5000)
}

func TestWithMaliciousPeer(t *testing.T){
	//TODO: 1. Add a malicious peer to the network (by a boolean console variable), which always adds his block to the shortest path. 2. Periodically print the status of the longest path and see that it doesn't change (because more peers are building at the longest path faster)
}


func MockTransactionObject() SignedTransaction{
	return SignedTransaction{newUUID(), "","",0,[]byte{}}
}

func MockNodeObject() *Node{
	return &Node{0,[]byte{}, BlockData{},[32]byte{},[][32]byte{},newUUID(),[]byte{}} // NewUUID makes sure each block has is different
}