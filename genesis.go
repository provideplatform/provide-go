package provide

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/ethereum/go-ethereum/accounts/abi"

	"github.com/jochasinga/requests"
	uuid "github.com/satori/go.uuid"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
)

const masterOfCeremonyGenesisAddress string = "0x9077F27fDD606c41822f711231eEDA88317aa67a"
const genesisContractAccountStartOffset = 9
const networkConsensusContractName = "NetworkConsensus"

func shellOut(bash string) error {
	cmd := exec.Command("bash", "-c", bash)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	_, err := cmd.Output()
	return err
}

func makeWorkdir() (string, error) {
	_uuid, err := uuid.NewV4()
	if err != nil {
		return "", err
	}
	path := fmt.Sprintf("./.tmp-%s", _uuid)
	err = os.Mkdir(path, 0755)
	return path, err
}

func gitClone(tmp, repoURL string, ref string) error {
	repo, err := git.PlainClone(tmp, false, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.ReferenceName(fmt.Sprintf("refs/tags/%s", ref)),
		SingleBranch:  true,
	})
	if err != nil {
		// requested ref is not a supported version... switching to edge mode
		shellOut(fmt.Sprintf("rm -rf ./%s", tmp))
		repo, err = git.PlainClone(tmp, false, &git.CloneOptions{
			URL:           repoURL,
			ReferenceName: plumbing.ReferenceName(fmt.Sprintf("refs/heads/%s", ref)),
			SingleBranch:  true,
		})
	}
	_, err = repo.Head()
	return err
}

func buildOS(tmp, ref string) error {
	err := gitClone(tmp, "https://github.com/providenetwork/auth-os", ref)
	if err != nil {
		return err
	}
	err = shellOut(fmt.Sprintf("pushd %s && npm prune && npm install && npm install truffle && npm install truffle-flattener && make flat && popd", tmp))
	return err
}

func buildNetworkConsensus(osWorkdir, tmp, ref string) error {
	err := gitClone(tmp, "https://github.com/providenetwork/network-consensus-contracts", ref)
	if err != nil {
		return err
	}
	err = shellOut(fmt.Sprintf("cp %s/flat/auth-os.sol %s/contracts/lib/auth_os.sol", osWorkdir, tmp))
	if err != nil {
		return err
	}
	err = shellOut(fmt.Sprintf("pushd %s && npm prune && npm install && npm install truffle && make compile && popd", tmp))
	return err
}

func fetchChainspec() (map[string]interface{}, error) {
	ref := os.Getenv("CHAINSPEC_REF")
	if ref == "" {
		ref = "master"
	}
	chainspecURL := fmt.Sprintf("https://raw.githubusercontent.com/providenetwork/chain-spec/%s/spec.json", ref)
	res, err := requests.Get(chainspecURL)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Failed to retrieve network chainspec from %s; status code: %v", chainspecURL, res.StatusCode)
	}
	var spec map[string]interface{}
	err = json.Unmarshal(res.Bytes(), &spec)
	if err != nil {
		return nil, err
	}
	return spec, nil
}

func getGenesisContractBytecode(path string) ([]byte, error) {
	compiledContractJSON, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var compiledContract map[string]interface{}
	err = json.Unmarshal(compiledContractJSON, &compiledContract)
	if err != nil {
		return nil, err
	}
	bytecode, ok := compiledContract["bytecode"].(string)
	if !ok {
		return nil, fmt.Errorf("Unable to read bytecode from compiled contract JSON: %s", path)
	}
	return []byte(bytecode), nil
}

func insertGenesisContractAccount(path, genesisAccountAddr string, genesisAccounts map[string]interface{}) error {
	bytecode, err := getGenesisContractBytecode(path)
	if err != nil {
		return err
	}
	genesisAccounts[genesisAccountAddr] = map[string]interface{}{
		"balance":     "1",
		"constructor": string(bytecode),
	}
	return nil
}

// BuildChainspec uses the given auth_os and network consensus refs to compile
// the bytecode for a dynamic set of contract accounts, and includes them in
// a generated chainspec based on a version of provide.network. The chainspec
// template has all of its contract accounts starting with 0x0000000000000000000000000000000000000009
// removed and replaced with bytecode dynamically generated based on the rules herein.
func BuildChainspec(osRef, consensusRef, masterOfCeremony string, genesisContractAccounts map[string]string) ([]byte, error) {
	var spec []byte
	var osWorkdir, consensusWorkdir string

	if osRef == "" {
		osRef = "master"
	}
	if consensusRef == "" {
		consensusRef = "master"
	}

	osWorkdir, err := makeWorkdir()
	if err == nil {
		err = buildOS(osWorkdir, osRef)
		consensusWorkdir, err = makeWorkdir()
		if err == nil {
			err = buildNetworkConsensus(osWorkdir, consensusWorkdir, consensusRef)
		}
		if err == nil {
			template, _ := fetchChainspec()
			accounts := template["accounts"].(map[string]interface{})

			delete(accounts, masterOfCeremonyGenesisAddress)
			accounts[masterOfCeremony] = map[string]interface{}{"balance": "1"}

			i := genesisContractAccountStartOffset
			ok := true
			for ok {
				delete(accounts, fmt.Sprintf("0x%040d", i))
				i++
				_, ok = accounts[fmt.Sprintf("0x%040d", i)]
			}

			for name, addr := range genesisContractAccounts {
				contractPath := fmt.Sprintf("%s/build/contracts/%s.json", consensusWorkdir, name)
				if _, err := os.Stat(contractPath); err == nil {
					if name != networkConsensusContractName {
						insertGenesisContractAccount(contractPath, addr, accounts)
					} else {
						var compiledContractABI []map[string]interface{}
						if compiledContractJSON, err := ioutil.ReadFile(contractPath); err == nil {
							if err := json.Unmarshal(compiledContractJSON, &compiledContractABI); err == nil {
								if compiledABIJSON, err := json.Marshal(compiledContractABI); err != nil {
									if consensusABI, err := abi.JSON(strings.NewReader(string(compiledABIJSON))); err != nil {
										encodedArgs, err := consensusABI.Constructor.Inputs.PackValues([]interface{}{
											masterOfCeremony,
											accounts["RegistryStorage"],
											accounts["InitRegistry"],
											accounts["AppConsole"],
											accounts["VersionConsole"],
											accounts["ImplConsole"],
											accounts["Aura"],
											accounts["ValidatorConsole"],
											accounts["VotingConsole"],
										})
										bytecode, err := getGenesisContractBytecode(contractPath)
										if err == nil {
											consensusGenesisConstructor := append(bytecode, encodedArgs...)
											accounts[addr] = map[string]interface{}{
												"balance":     "1",
												"constructor": string(consensusGenesisConstructor),
											}
										}
									}
								}
							}
						}

					}
				}
			}

			spec, err = json.Marshal(template)
			if err != nil {
				return nil, err
			}
		}
	}

	os.RemoveAll(osWorkdir)
	os.RemoveAll(consensusWorkdir)

	return spec, nil
}
