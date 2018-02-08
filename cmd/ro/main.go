package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/cmd/ro/gopass"
	"github.com/cloudflare/redoctober/cmd/ro/roagent"
	"github.com/cloudflare/redoctober/core"
	"github.com/cloudflare/redoctober/cryptor"
	"github.com/cloudflare/redoctober/msp"
	"github.com/cloudflare/redoctober/order"
	"golang.org/x/crypto/ssh"
)

var action, user, pswd, userEnv, pswdEnv, server, caPath, pubKeyPath string

var owners, lefters, righters, inPath, labels, usages, outPath, outEnv string

var uses, minUsers int

var duration, users, userType, hcName string

var pollInterval time.Duration

type command struct {
	Run  func()
	Desc string
}

var roServer *client.RemoteServer

var commandSet = map[string]command{
	"create":          command{Run: runCreate, Desc: "create the disk vault and admin account"},
	"create-user":     command{Run: runCreateUser, Desc: "create a user account"},
	"summary":         command{Run: runSummary, Desc: "list the user and delegation summary"},
	"delegate":        command{Run: runDelegate, Desc: "do decryption delegation"},
	"encrypt":         command{Run: runEncrypt, Desc: "encrypt a file"},
	"decrypt":         command{Run: runDecrypt, Desc: "decrypt a file"},
	"ssh-agent":       command{Run: runSSHAgent, Desc: "act as an SSH agent"},
	"ssh-add":         command{Run: runSSHAdd, Desc: "act as ssh-add"},
	"re-encrypt":      command{Run: runReEncrypt, Desc: "re-encrypt a file"},
	"order":           command{Run: runOrder, Desc: "place an order for delegations"},
	"owners":          command{Run: runOwner, Desc: "show owners list"},
	"status":          command{Run: runStatus, Desc: "show Red October persistent delegation state"},
	"restore":         command{Run: runRestore, Desc: "perform a restore delegation"},
	"reset-persisted": command{Run: runResetPersisted, Desc: "reset the persisted delegations"},
}

func registerFlags() {
	flag.StringVar(&server, "server", "localhost:8080", "server address")
	flag.StringVar(&caPath, "ca", "", "ca file path")
	flag.StringVar(&owners, "owners", "", "comma separated owner list")
	flag.StringVar(&users, "users", "", "comma separated user list")
	flag.IntVar(&uses, "uses", 0, "number of delegated key uses")
	flag.IntVar(&minUsers, "minUsers", 2, "minimum number of delegations")
	flag.StringVar(&duration, "time", "0h", "duration of delegated key uses")
	flag.StringVar(&lefters, "left", "", "comma separated left owners")
	flag.StringVar(&righters, "right", "", "comma separated right owners")
	flag.StringVar(&labels, "labels", "", "comma separated labels")
	flag.StringVar(&usages, "usages", "", "comma separated usages")
	flag.StringVar(&inPath, "in", "", "input data file")
	flag.StringVar(&outPath, "out", "", "output data file")
	flag.StringVar(&outEnv, "outenv", "", "env variable for output data")
	flag.StringVar(&user, "user", "", "username")
	flag.StringVar(&pswd, "password", "", "password")
	flag.StringVar(&userType, "userType", "rsa", "user key type: ecc or rsa")
	flag.StringVar(&hcName, "hipchat-name", "", "hipchat name for user, used for notifications")
	flag.StringVar(&userEnv, "userenv", "RO_USER", "env variable for user name")
	flag.StringVar(&pswdEnv, "pswdenv", "RO_PASS", "env variable for user password")
	flag.DurationVar(&pollInterval, "poll-interval", time.Second, "interval for polling an outstanding order (set 0 to disable polling)")
	flag.StringVar(&pubKeyPath, "pubkey", "id_rsa.pub", "path to SSH public key")
}

func readLine(prompt string) (line string, err error) {
	fmt.Fprintf(os.Stderr, prompt)
	rd := bufio.NewReader(os.Stdin)
	line, err = rd.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	return
}

func getUserCredentials() {
	var err error
	if user == "" {
		user = os.Getenv(userEnv)
	}

	if pswd == "" {
		pswd = os.Getenv(pswdEnv)
	}

	if user == "" {
		user, err = readLine("Username: ")
		processError("error", err)
	}

	if pswd == "" {
		pswd, err = gopass.GetPass("Password: ")
		processError("error", err)
	}
}

func processError(msg string, err error) {
	if err != nil {
		log.Fatalln(msg, ":", err)
	}
}

func processCSL(s string) []string {
	if s == "" {
		return nil
	}

	return strings.Split(s, ",")
}

func runCreate() {
	req := core.CreateRequest{
		Name:     user,
		Password: pswd,
	}
	resp, err := roServer.Create(req)
	processError("error", err)
	fmt.Println(resp.Status)
}

func runCreateUser() {
	req := core.CreateUserRequest{
		Name:        user,
		Password:    pswd,
		UserType:    userType,
		HipchatName: hcName,
	}
	resp, err := roServer.CreateUser(req)
	processError("error", err)
	fmt.Println(resp.Status)
}

func runDelegate() {
	req := core.DelegateRequest{
		Name:     user,
		Password: pswd,
		Uses:     uses,
		Time:     duration,
		Users:    processCSL(users),
		Labels:   processCSL(labels),
	}
	resp, err := roServer.Delegate(req)
	processError("error", err)
	fmt.Println(resp.Status)
}

func runRestore() {
	req := core.DelegateRequest{
		Name:     user,
		Password: pswd,
		Uses:     uses,
		Time:     duration,
	}

	resp, err := roServer.Restore(req)
	processError("error", err)

	if resp.Status != "ok" {
		fmt.Fprintf(os.Stderr, "failed: %s\n", resp.Status)
		os.Exit(1)
	}

	var st core.StatusData
	err = json.Unmarshal(resp.Response, &st)
	processError("error", err)

	fmt.Println("Restore delegation complete; persistence is now", st.Status)
}

// TODO: summary response needs better formatting
func runSummary() {
	req := core.SummaryRequest{
		Name:     user,
		Password: pswd,
	}
	resp, err := roServer.Summary(req)
	processError("error", err)
	fmt.Println(resp)
}

func runEncrypt() {
	inBytes, err := ioutil.ReadFile(inPath)
	processError("error", err)
	req := core.EncryptRequest{
		Name:        user,
		Password:    pswd,
		Minimum:     minUsers,
		Owners:      processCSL(owners),
		Usages:      processCSL(usages),
		LeftOwners:  processCSL(lefters),
		RightOwners: processCSL(righters),
		Labels:      processCSL(labels),
		Data:        inBytes,
	}

	resp, err := roServer.Encrypt(req)
	processError("error", err)
	if resp.Status != "ok" {
		log.Fatalln("response status error", resp.Status)
		return
	}
	fmt.Println("Response Status:", resp.Status)
	outBytes := []byte(base64.StdEncoding.EncodeToString(resp.Response))
	ioutil.WriteFile(outPath, outBytes, 0644)
}

func runReEncrypt() {
	inBytes, err := ioutil.ReadFile(inPath)
	processError("error", err)

	// base64 decode the input
	encBytes, err := base64.StdEncoding.DecodeString(string(inBytes))
	if err != nil {
		log.Println("fail to base64 decode the data, proceed with raw data")
		encBytes = inBytes
	}

	req := core.ReEncryptRequest{
		Name:        user,
		Password:    pswd,
		Owners:      processCSL(owners),
		Minimum:     minUsers,
		LeftOwners:  processCSL(lefters),
		RightOwners: processCSL(righters),
		Labels:      processCSL(labels),
		Data:        encBytes,
	}

	resp, err := roServer.ReEncrypt(req)
	processError("error", err)
	if resp.Status != "ok" {
		log.Fatalln("response status error", resp.Status)
		return
	}
	fmt.Println("Response Status:", resp.Status)
	outBytes := []byte(base64.StdEncoding.EncodeToString(resp.Response))
	ioutil.WriteFile(outPath, outBytes, 0644)
}

func runDecrypt() {
	inBytes, err := ioutil.ReadFile(inPath)
	processError("error", err)

	// base64 decode the input
	encBytes, err := base64.StdEncoding.DecodeString(string(inBytes))
	if err != nil {
		log.Println("fail to base64 decode the data, proceed with raw data")
		encBytes = inBytes
	}

	req := core.DecryptRequest{
		Name:     user,
		Password: pswd,
		Data:     encBytes,
	}

	resp, err := roServer.Decrypt(req)
	if err != nil {
		switch err.Error() {
		case cryptor.ErrNotEnoughDelegations.Error(),
			msp.ErrNotEnoughShares.Error(),
			"need more delegated keys":
			// retry forever unless keyboard interrupt
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

			for i := 0; i < 20; i++ {
				resp, err = roServer.Decrypt(req)
				if err == nil {
					break
				}
				log.Println("retry after 30 seconds due to error: ", err)

				select {
				case <-sigChan:
					log.Fatalln("process is interrupted")
					return

				case <-time.After(30 * time.Second):
				}
			}
		default:
			processError("error", err)
		}
	}

	if resp == nil {
		log.Fatalln("response status error", resp.Status)
	}

	fmt.Println("Response Status:", resp.Status)
	var msg core.DecryptWithDelegates
	err = json.Unmarshal(resp.Response, &msg)
	processError("error", err)
	fmt.Println("Secure:", msg.Secure)
	fmt.Println("Delegates:", msg.Delegates)
	ioutil.WriteFile(outPath, msg.Data, 0644)
}

func runOrder() {
	req := core.OrderRequest{
		Name:     user,
		Password: pswd,
		Uses:     uses,
		Duration: duration,
		Labels:   processCSL(labels),
		Users:    processCSL(users),
	}
	resp, err := roServer.Order(req)
	processError("error", err)

	var o order.Order
	err = json.Unmarshal(resp.Response, &o)
	processError("error", err)

	if pollInterval > 0 {
		for o.Delegated < 2 {
			time.Sleep(pollInterval)
			resp, err = roServer.OrderInfo(core.OrderInfoRequest{Name: user, Password: pswd, OrderNum: o.Num})
			processError("error", err)
			err = json.Unmarshal(resp.Response, &o)
			processError("error", err)
		}
	}
	fmt.Println(resp.Status)
}

func runOwner() {
	inBytes, err := ioutil.ReadFile(inPath)
	processError("error", err)

	// attempt to base64 decode the input file
	base64decoded, err := base64.StdEncoding.DecodeString(string(inBytes))
	if err == nil {
		inBytes = base64decoded
	}

	req := core.OwnersRequest{
		Data: inBytes,
	}

	resp, err := roServer.Owners(req)
	processError("error", err)

	fmt.Println(resp.Status)
	fmt.Println(resp)
}

func runStatus() {
	req := core.StatusRequest{
		Name:     user,
		Password: pswd,
	}

	resp, err := roServer.Status(req)
	processError("error", err)

	fmt.Println(resp.Status)
	fmt.Println(resp)
}

func runResetPersisted() {
	req := core.PurgeRequest{
		Name:     user,
		Password: pswd,
	}

	resp, err := roServer.ResetPersisted(req)
	processError("error", err)

	fmt.Println(resp.Status)
	fmt.Println(resp)
}

func runSSHAgent() {
	log.Println("Starting Red October Secret Shell Agent")

	// Prepare a socket
	dir, err := ioutil.TempDir("", "ro_ssh_")
	processError("error making a temporary directory", err)

	authSockPath := path.Join(dir, "roagent.sock")
	os.Setenv("SSH_AUTH_SOCK", authSockPath)
	fmt.Printf("export SSH_AUTH_SOCK=%s\n", authSockPath)

	socket := net.UnixAddr{Net: "unix", Name: authSockPath}
	ear, err := net.ListenUnix("unix", &socket)
	processError("error making a unix socket", err)

	// Make an agent
	roAgent := roagent.NewROAgent(roServer, user, pswd)

	// Process the arguments
	if inPath != "" && pubKeyPath != "" {
		go runSSHAdd()
	}

	// Prepare for signal interception
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func(ear net.Listener, c chan os.Signal) {
		sig := <-c
		log.Printf("Caught signal %s: shutting down.", sig)
		os.RemoveAll(path.Dir(authSockPath))
		ear.Close()
		os.Exit(0)
	}(ear, sigChan)

	// Serve the agent
	for {
		conn, err := ear.AcceptUnix()
		processError("error accepting socket connection", err)
		go roagent.ServeAgent(roAgent, conn)
	}
}

func runSSHAdd() {
	// Process the arguments
	inBytes, err := ioutil.ReadFile(inPath)
	processError("error reading encrypted data", err)

	encBytes, err := base64.StdEncoding.DecodeString(string(inBytes))
	if err != nil {
		log.Println("error base64-decoding the data, proceeding with raw data")
		encBytes = inBytes
	}

	inBytes, err = ioutil.ReadFile(pubKeyPath)
	processError("error reading public key", err)

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(inBytes)
	processError("error parsing public key", err)

	// Prepare a socket
	authSockPath := os.Getenv("SSH_AUTH_SOCK")

	socket := net.UnixAddr{Net: "unix", Name: authSockPath}
	mouth, err := net.DialUnix("unix", nil, &socket)
	processError("error connecting to unix socket", err)

	// Contact the agent
	newROAgent := roagent.NewClient(mouth)
	rosigner := roagent.NewROSigner(pubKey, encBytes)
	err = newROAgent.Add(roagent.AddedKey{
		PrivateKey: rosigner,
	})
	processError("failed to add new signer to the ROAgent", err)

	fmt.Println("New signer was added to the ROAgent")
}

func main() {
	flag.Usage = func() {
		fmt.Println("Usage: ro [options] subcommand")
		fmt.Println("Currently supported subcommands are:")
		for key := range commandSet {
			fmt.Println("\t", key, ":", commandSet[key].Desc)
		}

		fmt.Println("Options:")
		flag.PrintDefaults()
	}

	registerFlags()
	flag.Parse()

	action := flag.Arg(0)

	if flag.NArg() != 1 && action != "ssh" {
		flag.Usage()
		os.Exit(1)
	}

	cmd, found := commandSet[action]
	if !found {
		fmt.Println("Unsupported subcommand:", action)
		flag.Usage()
		os.Exit(1)
	} else {
		var err error
		roServer, err = client.NewRemoteServer(server, caPath)
		processError("error", err)

		getUserCredentials()
		cmd.Run()
	}
}
