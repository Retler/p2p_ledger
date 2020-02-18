package main

import (
	"fmt"
	"net"
	"regexp"
	"sync"
	"bufio"
	"os"
	"strings"
	"encoding/gob"
	"io"
	"sort"
	"log"
	"time"
	"strconv"
	"crypto/rand"
	"math/big"
)

// Method types: 0=Transaction, 1=Peer list request, 2=Presence broadcast request, 3=Peer list response

func validateAddress(address string) (bool, error) {
	return regexp.MatchString("[0-9]+.[0-9]+.[0-9]+.[0-9]+:[0-9]+", address)
}

type Ledger struct {
	Accounts map[[32]byte]int // !!! This is modified so the account is now identified by the public key
	lock sync.Mutex
}

func MakeLedger() *Ledger {
	ledger := new(Ledger)
	ledger.Accounts = make(map[[32]byte]int)
	return ledger
}

type Message struct {
	From string
	FromOrigin string
	MessageType int
	TransactionObject SignedTransaction
	PeersFromRemote []string
	MessageId string
	PublicKey []byte
	PublicKeys map[string][]byte
	Block Node
}

type SignedTransaction struct {
	ID string
	From string
	To string
	Amount int
	Signature []byte
}

type Peers struct{
	peers []net.Conn
	lock sync.RWMutex
}

type Block struct {
	BlockNumber int
	Messages []string
	Signature []byte
}

func MakePeers() *Peers{
	peers := new(Peers)
	peers.peers = make([]net.Conn, 5)
	return peers
}

var ledger = MakeLedger()
var messageQueue chan Message
var peers = MakePeers()
var peerList = make([]string, 0)
var self = ""
var sentMessages = make(map[string]bool)
var publicKeys = make(map[string]big.Int) // Lets keep public keys here
var dummyBigint = new(big.Int).SetBytes([]byte{0})
var unhandledTransactions = make(map[string]SignedTransaction)
var tree = MakeFreshTree()
var malicious = false

func TransactionAsBigint(t *SignedTransaction) big.Int{
	bytes := []byte(t.ID)
	bytes = append(bytes,[]byte(strconv.Itoa(t.Amount))...)
	bytes = append(bytes, []byte(t.To)...)
	bytes = append(bytes, []byte(t.From)...)
	return *new(big.Int).SetBytes(bytes)
}

func GenerateSignature(t *SignedTransaction) []byte{
	transactionAsBigint := TransactionAsBigint(t)
	transactionSignature := Sign(transactionAsBigint)
	transactionSignatureInBytes := transactionSignature.Bytes()
	return transactionSignatureInBytes
}

func (l *Ledger) SignedTransaction(t *SignedTransaction) {
	validSignature := false
	l.lock.Lock() ; defer l.lock.Unlock()

	publicKey := publicKeys[t.From] // We get the peers public key
	transactionAsBigint := TransactionAsBigint(t) // We convert the transaction to a big.Int object
	unverifyedHash := Encrypt(*new(big.Int).SetBytes(t.Signature),publicKey) // We use the peers public key on the transaction signature
	shavalueOfMessage := Sha256Hash(transactionAsBigint.Bytes()) // We calulate the actual sha-value of the message
	supposedToBeHash := new(big.Int).SetBytes(shavalueOfMessage[:]); // This is what the hash of the message should be
	publicKeyFrom := publicKeys[t.From]
	publicKeyTo := publicKeys[t.To]
	hashOfPublicKeyFrom := Sha256Hash(publicKeyFrom.Bytes())
	hashOfPublicKeyTo := Sha256Hash(publicKeyTo.Bytes())

	negativeResult := (l.Accounts[hashOfPublicKeyFrom] - t.Amount) < 0

	if unverifyedHash.Cmp(supposedToBeHash) == 0{
		validSignature = true
	}
	if validSignature && !negativeResult {
		l.Accounts[hashOfPublicKeyFrom] -= t.Amount
		l.Accounts[hashOfPublicKeyTo] += t.Amount
		fmt.Println("Transaction succes. Transfered ", t.Amount, " from ", t.From, " to ", t.To)
	}else{
		fmt.Println("Invalid signature or negative account result!")
	}
}
func (l *Ledger) RevertTransaction(t *SignedTransaction) {
	validSignature := false
	l.lock.Lock() ; defer l.lock.Unlock()

	publicKey := publicKeys[t.From] // We get the peers public key
	transactionAsBigint := TransactionAsBigint(t) // We convert the transaction to a big.Int object
	unverifyedHash := Encrypt(*new(big.Int).SetBytes(t.Signature),publicKey) // We use the peers public key on the transaction signature
	shavalueOfMessage := Sha256Hash(transactionAsBigint.Bytes()) // We calulate the actual sha-value of the message
	supposedToBeHash := new(big.Int).SetBytes(shavalueOfMessage[:]); // This is what the hash of the message should be
	publicKeyFrom := publicKeys[t.From]
	publicKeyTo := publicKeys[t.To]
	hashOfPublicKeyFrom := Sha256Hash(publicKeyFrom.Bytes())
	hashOfPublicKeyTo := Sha256Hash(publicKeyTo.Bytes())

	negativeResult := (l.Accounts[hashOfPublicKeyFrom] - t.Amount) < 0

	if unverifyedHash.Cmp(supposedToBeHash) == 0{
		validSignature = true
	}
	if validSignature && !negativeResult {
		l.Accounts[hashOfPublicKeyFrom] += t.Amount
		l.Accounts[hashOfPublicKeyTo] -= t.Amount
		fmt.Println("Reverse transaction succes. Transfered ", t.Amount, " from ", t.To, " to ", t.From)
	}else{
		fmt.Println("Invalid signature or negative account result!")
	}
}

func publicKeysToBytes(publicKeys map[string]big.Int) map[string][]byte{
	result := make(map[string][]byte)
	for k, v := range publicKeys {
		result[k]=v.Bytes()
	}
	return result
}

func main() {
	fmt.Println("Input ip and portnumber of peer")
	var input string
	fmt.Scanln(&input)
	messageQueue = make(chan Message)

	match, err := validateAddress(input)
	conn, connErr := net.Dial("tcp", input)

	var connectionListener net.Listener
	connectionListener, _ = net.Listen("tcp", ":")

	n,d = MakePublicPrivateRsaKeys(1000)

	go printBalanceEvery10()
	CreateSmallTree()

	if !match || (err != nil) || (connErr != nil) { // Starting a network
		// start new network
		malicious = true // The starter of the network will be the malicious peer
		fmt.Println("Invalid address. Starting a new network on adress: " + connectionListener.Addr().String())
		waitForFirstConnection(connectionListener)
		go listenForNewConnections(connectionListener)
	} else { // Network exists, so just connect to it..
		self = strings.Split(conn.LocalAddr().String(),":")[0] + ":" +  strings.Split(connectionListener.Addr().String(),":")[3]
		publicKeys[self] = n
		fmt.Println("Successfully connected to peer ", conn.RemoteAddr().String())
		go handleConnection(conn)
		addPeer(conn)
		makePeerListRequest(conn)
		go listenForNewConnections(connectionListener)
	}

	go startLotteryDraw()
	go printTreeSizeAndTree()

	publicKeySelf := publicKeys[self]
	ledger.Accounts[Sha256Hash(publicKeySelf.Bytes())] = 10000000

	go broadcast(messageQueue)

	fmt.Println("Now you can send transactions by inputting ip:portnumber followed by an ammount. ")

	for{
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n') // input has to be of form: [receiver] [ammount]
		receiver := strings.Split(input, " ")[0]
		ammount, err := strconv.Atoi(strings.TrimSuffix(strings.Split(input, " ")[1], "\r\n"))

		if err != nil { fmt.Println(err); continue }

		message := Message{self,self, 0 ,SignedTransaction{newUUID(),self,receiver,ammount, dummyBigint.Bytes()}, []string{},newUUID(),dummyBigint.Bytes(),publicKeysToBytes(publicKeys), Node{}}
		message.TransactionObject.Signature = GenerateSignature(&message.TransactionObject)
		messageQueue <- message
	}
}
func printBalanceEvery10() {
	for range time.Tick(10*time.Second) {
		 printAccountBalances()
	}
}

func makePeerListRequest(conn net.Conn) {
	enc := gob.NewEncoder(conn)
	err := enc.Encode(Message{conn.LocalAddr().String(),self,1,SignedTransaction{}, []string{}, newUUID(),dummyBigint.Bytes(),publicKeysToBytes(publicKeys), Node{}})
	if err != nil {
		fmt.Print("Error encoding peerlistrequest, ", err)
	}
}

func printTreeSizeAndTree(){
	for _ = range time.Tick(15*time.Second) {
		fmt.Println("Blocks added to tree so far: ", tree.Size())
		fmt.Println("Current best path lenght is: ", tree.BestPath(tree.Genesis).pathLength)
		fmt.Println("Current leftmost path lenght is: ", tree.LeftMostPathLength())
	}
}

func startLotteryDraw(){
	hardness := new(big.Int).SetBytes(tree.Genesis.BlockData.Hardness)
	slotCount := 0
 	for _ = range time.Tick(2*time.Second) { // We make a draw every other second

		draw := makeDraw(tree.Genesis.BlockData.Seed, slotCount)
		drawValue := getDrawValue(draw, n, tree.Genesis.BlockData.Seed, slotCount)
		if (drawValue.Cmp(hardness) == 1){ // if drawValue > hardness, then send a block
		fmt.Println("This peer just won the lottery at slot ", slotCount)
			p := tree.BestPath(tree.Genesis)
			b := tree.BestLeaf()
			if(malicious){
				fmt.Println("Malicious peer adding block to leftmost leaf!")
				b = tree.LeftmostLeaf()
			} // If the peer is malicious, the node will always be added to the left. The malicious peer wants to grow the tree in that direction.
			u := TransactionSetMinus(unhandledTransactions, DeliveredTransactionsInPath(p.path)) // received \ delivered
			h := b.GenerateNodeHash()
			block := MakeBlock(slotCount,draw,u,h,self) // Creates a block with given values.
			tree.AddNode(block)
			removeTransactionsFromUnhandled(&block.BlockData.Transactions)
			sendBlockToNetwork(*block)
		}

		slotCount += 1
	}
}

func removeTransactionsFromUnhandled(transactions *[]SignedTransaction) {
	for _,v := range *transactions{
		delete(unhandledTransactions,v.ID)
	}
}
func sendBlockToNetwork(block Node) {
	message := Message{self,self,4,SignedTransaction{}, []string{}, newUUID(),dummyBigint.Bytes(),map[string][]byte{}, block}
	messageQueue <- message
}

func getDrawValue(draw big.Int, publicKey big.Int, seed int, slot int) big.Int{
	unsignedDraw := generateDrawToSign(seed, slot)
	drawVerifyed := verifyDraw(draw, unsignedDraw, publicKey)
	if(!drawVerifyed){
		fmt.Println("Couldn't verify signature of the draw")
		return *dummyBigint
	} // Bail out if signature cannot be verifyed
	tickets := ledger.Accounts[Sha256Hash(publicKey.Bytes())]
	ticketsAsBigInt := new(big.Int).SetInt64(int64(tickets)) // Tickets

	// Calculating hash of (Lottery,Seed,slot,P_i,Draw)
	lotteryAsBytes := []byte("Lottery") // "Lottery"
	seedAsBigInt := new(big.Int).SetInt64(int64(seed))
	seedAsBytes := seedAsBigInt.Bytes() // Seed
	slotAsBigInt := new(big.Int).SetInt64(int64(slot))
	slotAsBytes := slotAsBigInt.Bytes() // Slot
	publicKeyAsBytes := publicKey.Bytes() // The P_i part is represented as P_i's public key
	drawAsBytes := draw.Bytes() // Draw
	tempBytes := make([]byte, 0)
	tempBytes = append(tempBytes, lotteryAsBytes...)
	tempBytes = append(tempBytes, seedAsBytes...)
	tempBytes = append(tempBytes, slotAsBytes...)
	tempBytes = append(tempBytes, publicKeyAsBytes...)
	tempBytes = append(tempBytes, drawAsBytes...)
	hashToMultiply := Sha256Hash(tempBytes) // H(Lottery, Seed, Slot, P_i, Draw)
	hashToMultiplyAsBigInt := new(big.Int).SetBytes(hashToMultiply[:])
	result := new(big.Int).Mul(ticketsAsBigInt, hashToMultiplyAsBigInt) // Tickets * H(Lottery, Seed, Slot, P_i, Draw)

	return *result
}
func verifyDraw(draw big.Int, drawValue big.Int, publicKey big.Int) bool {
	verifyedDraw := Encrypt(draw, publicKey)
	drawValueAsHash := Sha256Hash(drawValue.Bytes())
	hashAsBigInt := new(big.Int).SetBytes(drawValueAsHash[:])
	return verifyedDraw.Cmp(hashAsBigInt) == 0
}

func generateDrawToSign(seed int, slot int) big.Int{
	bigIntSeed := new(big.Int).SetInt64(int64(seed))
	bigIntSlot := new(big.Int).SetInt64(int64(slot))
	seedBytes := bigIntSeed.Bytes()
	slotBytes := bigIntSlot.Bytes()
	lotteryBytes := []byte("Lottery")

	result := make([]byte, 0)
	result = append(result, seedBytes...)
	result = append(result, slotBytes...)
	result = append(result, lotteryBytes...)

	resultBigInt := new(big.Int).SetBytes(result)

	return *resultBigInt
}

func makeDraw(seed int, slot int) big.Int{
	unsignedDraw := generateDrawToSign(seed,slot)
	draw := Sign(unsignedDraw)
	return draw
}

func printAccountBalances(){
	ledger.lock.Lock()
	for k,v := range ledger.Accounts{
		fmt.Println("Printing balance of all accounts (every 10 sec):")
		fmt.Println("Account: ", k, " Balance: ", v)
	}
	ledger.lock.Unlock()
}

func connectToOtherPeers(peersFromRemote []string, remoteAddr string) {
	sortPeers(peersFromRemote);

	listToConnectTo := getTenPeersAfterMe(peersFromRemote, remoteAddr);

	for _, peer := range listToConnectTo{
		fmt.Println("Connecting to peer: ", peer)
		conn, connErr := net.Dial("tcp", peer)

		if connErr != nil {
			log.Fatal("Error connecting to peer " + peer)
			continue
		}

		go handleConnection(conn)

		addPeer(conn)
	}
}

func getTenPeersAfterMe(peersFromRemote []string, remoteAddr string) []string {
	result := make([]string, 0);

	for index, peer := range peersFromRemote {
		if 	peer == self{ // Find yourself on the list
			for i := 1; i < 10; i++{
				if peersFromRemote[(index+i)%len(peersFromRemote)] == self{ break }
				if peersFromRemote[(index+i)%len(peersFromRemote)] == remoteAddr { continue }
				if contains(peersFromRemote,peersFromRemote[(index+i)%len(peersFromRemote)]){ continue }
				result = append(result,peersFromRemote[(index+i)%len(peersFromRemote)])
			}
			return result;
		}
	}
	return result; // We will never get here because of the invariant that self is always in the list.
}

func contains(peerList []string, peer string) bool{
	for _,peer2 := range peerList{
		if peer2 == peer{
			return true
		}
	}
	return false
}

func sortPeers(peers []string){
	sort.Strings(peers);
}

func listenForNewConnections(connectionListener net.Listener){
	fmt.Println("Listening for peers at: " + connectionListener.Addr().String())
	defer connectionListener.Close()
	for{
		conn, _ := connectionListener.Accept()
		fmt.Println("Connection from " + conn.RemoteAddr().String() + " accepted")
		addPeer(conn)

		go handleConnection(conn)
	}
}

func broadcast(c chan Message) {

	for {
		message := <-c

		if !sentMessages[message.MessageId]{
			handleMessage(message)
		}
	}
}
func handleMessage(message Message) {
	switch message.MessageType {
	case 0:
		handleTransactionMessage(message)
	case 1:
		handlePeerListRequestMessage(message)
	case 2:
		handleBroadcastingAddressMessage(message)
	case 3:
		handlePeerListResponse(message)
	case 4:
		if(!sentMessages[message.MessageId]){ // If we sent the block it means we already handled it
			handleBlock(message)
		}

	default:
		fmt.Errorf("Unsupported message type: %d ", message.MessageType)
	}
}

func handleBlock(message Message) {
	block := message.Block
	blockOwnerPublicKey := publicKeys[block.Creator]

	verifyed := VerifyBlock(block, blockOwnerPublicKey)
	drawValue := getDrawValue(*new(big.Int).SetBytes(block.Draw), blockOwnerPublicKey, tree.Genesis.BlockData.Seed, block.Slot)
	hardness := new(big.Int).SetBytes(tree.Genesis.BlockData.Hardness)

	if (verifyed && drawValue.Cmp(hardness) == 1) { // The signature is verifyed and we passed the hardness threshold
		tree.AddNode(&block)
		removeTransactionsFromUnhandled(&block.BlockData.Transactions)
	}

	if(tree.Size() % 10 == 0){ // Execute transactions every 10 blocks made - just for testing purposes
		tree.MakeTransactions()
	}

	sendMessageToPeers(message)
}

func VerifyBlock(block Node, blockOwnerPublicKey big.Int) bool {
	hashOfBlock := Sha256Hash(block.toBytes())
	hashToVerifyAsBigInt := Encrypt(*new(big.Int).SetBytes(block.Signature), blockOwnerPublicKey)
	hashToVerify := [32]byte{}
	copy(hashToVerify[:], hashToVerifyAsBigInt.Bytes()[:32])
	verifyed := hashOfBlock == hashToVerify
	return verifyed
}

func handlePeerListResponse(message Message) {
	peerList = message.PeersFromRemote
	peerList = append(peerList,self)
	for k,v := range publicKeyBytesToBigints(message.PublicKeys){
		publicKeys[k] = v
	}
	ledger.lock.Lock()

	for _,v := range message.PublicKeys{
		hashOfPublicKey := Sha256Hash(v)
		ledger.Accounts[hashOfPublicKey] = 10000000
	}
	ledger.lock.Unlock()
	connectToOtherPeers(peerList, message.From)
	broadcastPresence()
}
func publicKeyBytesToBigints(bytes map[string][]byte) map[string]big.Int {
	result := make(map[string]big.Int)
	for v,k := range bytes{
		result[v] = *new(big.Int).SetBytes(k)
	}
	return result
}

func broadcastPresence() {
	publicKeys[self] = n

	for _, peer := range peers.peers {
		if peer != nil {
			if peer != nil && peer.RemoteAddr().String() != self{
				message := Message{self,self,2, SignedTransaction{},[]string{}, newUUID(),n.Bytes(),nil, Node{}}
				enc := gob.NewEncoder(peer)
				enc.Encode(message)
			}
		}
	}
}
func handleBroadcastingAddressMessage(message Message) {
	fmt.Println("Handling broadcasting address message")
	if message.FromOrigin != self{
		peerList = append(peerList, message.FromOrigin)
		publicKeys[message.FromOrigin] = *new(big.Int).SetBytes(message.PublicKey)
		shaOfPublicKey := Sha256Hash(message.PublicKey)
		ledger.lock.Lock()
		ledger.Accounts[shaOfPublicKey] = 10000000
		ledger.lock.Unlock()
		sendMessageToPeers(message)
	}
}
func handlePeerListRequestMessage(message Message) {
	fmt.Println("Handling peerlistrequest...")
	for _, peer := range peers.peers {
		if peer != nil && peer.RemoteAddr().String() == message.From {
			msg := Message{self,self, 3, SignedTransaction{}, peerList, newUUID(),dummyBigint.Bytes(), publicKeysToBytes(publicKeys), Node{}}
			enc := gob.NewEncoder(peer)
			enc.Encode(msg)
		}
	}
}

func handleTransactionMessage(message Message) {
	unhandledTransactions[message.TransactionObject.ID] = message.TransactionObject
	sendMessageToPeers(message)
}

func debug(debugMsg string){
	fmt.Println("Debugger: " + debugMsg)
}

func sendMessageToPeers(message Message){
	for _, conn := range peers.peers {

		if (conn != nil) && !sentMessages[message.MessageId] { // Added this check so the sender of the message doesnt get it back
			message.From = self
			encoder := gob.NewEncoder(conn)
			encoder.Encode(message)
		}
	}
	sentMessages[message.MessageId] = true
}

func handleConnection(conn net.Conn) {
	debug("handling connection to: " + conn.RemoteAddr().String())
	defer conn.Close()


	for {
		msg := &Message{}
		dec := gob.NewDecoder(conn)
		err := dec.Decode(msg)

		if err == io.EOF {
			fmt.Println("Connection closed by " + conn.RemoteAddr().String())
		}

		if err != nil {
			fmt.Println(err.Error())
			return
		}

		messageQueue <- *msg
	}
}

func waitForFirstConnection(connectionListener net.Listener){
	fmt.Println("Waiting for initial connection..")
	conn, _ := connectionListener.Accept()
	self = conn.LocalAddr().String()
	peerList = append(peerList, self)
	self = conn.LocalAddr().String()
	publicKeys[self] = n
	addPeer(conn)

	go handleConnection(conn)
	fmt.Println("Connection from " + conn.RemoteAddr().String() + " accepted")
}

func addPeer(conn net.Conn){
	peers.lock.Lock()
	peers.peers = append(peers.peers, conn)
	peers.lock.Unlock()
}

// Used to generate unique id's for messages, so we can use these to create sentMessages map
func newUUID() string {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return ""
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}



