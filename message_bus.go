package provide

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/dgrijalva/jwt-go"
	shell "github.com/ipfs/go-ipfs-api"
	uuid "github.com/kthomas/go.uuid"
)

const applicationTypeMessageBus = "message_bus"
const connectorTypeIPFS = "ipfs"
const contractTypeRegistry = "registry"
const defaultMessagesPerPage = 1000000
const publishContractMethod = "publish"

// MessageBus client
type MessageBus struct {
	application   map[string]interface{}
	applicationID *uuid.UUID

	connector       map[string]interface{}
	connectorID     *uuid.UUID
	connectorAPIURL *string

	contract   map[string]interface{}
	contractID *uuid.UUID

	token         string
	accountAddress string
}

// NewMessageBus initializes a new message bus client configured using the given API token
func NewMessageBus(token, accountAddress string) (*MessageBus, error) {
	jwtToken, err := jwt.Parse(token, func(_jwtToken *jwt.Token) (interface{}, error) {
		// no need to verify client-side
		return nil, nil
	})

	if jwtToken == nil {
		return nil, fmt.Errorf("invalid jwt: %s", token)
	}

	var applicationID *uuid.UUID
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok {
		if sub, subok := claims["sub"].(string); subok {
			subprts := strings.Split(sub, ":")
			if len(subprts) != 2 {
				return nil, fmt.Errorf("jwt subject malformed; %s", sub)
			}
			if subprts[0] != "application" {
				return nil, fmt.Errorf("jwt claims specified non-application subject: %s", subprts[0])
			}
			id, err := uuid.FromString(subprts[1])
			if err != nil {
				return nil, fmt.Errorf("invalid application id; %s", err.Error())
			}
			applicationID = &id
		}
	}

	if applicationID == nil {
		return nil, fmt.Errorf("failed to initialize message bus; no application id resolved in otherwise-valid jwt claims; token: %s", token)
	}

	if accountAddress == "" {
		return nil, fmt.Errorf("failed to initialize message bus; invalid account address provided for message bus id: %s", applicationID)
	}

	mb := &MessageBus{
		applicationID: applicationID,
		token:         token,
		accountAddress: accountAddress,
	}

	err = mb.resolveApplication()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize message bus; application resolution failed: %s", err.Error())
	}
	if mb.application == nil || mb.applicationID == nil || *mb.applicationID == uuid.Nil {
		return nil, fmt.Errorf("failed to retrieve message bus application with id: %s", mb.applicationID)
	}

	err = mb.resolveContract()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize message bus; contract resolution failed: %s", err.Error())
	}
	if mb.contract == nil || mb.contractID == nil || *mb.contractID == uuid.Nil {
		return nil, fmt.Errorf("failed to retrieve on-chain registry contract for message bus application with id: %s", mb.applicationID)
	}

	err = mb.resolveConnector()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize message bus; connector resolution failed: %s", err.Error())
	}
	if mb.contract == nil || mb.contractID == nil || *mb.contractID == uuid.Nil {
		return nil, fmt.Errorf("failed to retrieve distributed filesystem connector for message bus application with id: %s", mb.applicationID)
	}

	config, configOk := mb.application["config"].(map[string]interface{})
	if !configOk {
		return nil, fmt.Errorf("failed to parse message bus application config for message bus application with id: %s", mb.applicationID)
	}

	if applicationType, applicationTypeOk := config["type"].(string); applicationTypeOk && applicationType != applicationTypeMessageBus {
		return nil, fmt.Errorf("retrieved application with id %s, but it was not a message bus application", mb.applicationID)
	}

	if connectorCfg, connectorCfgOk := mb.connector["config"].(map[string]interface{}); connectorCfgOk {
		if connectorAPIURL, connectorAPIURLOk := connectorCfg["api_url"].(string); connectorAPIURLOk {
			mb.connectorAPIURL = &connectorAPIURL
		}
	}
	if mb.connectorAPIURL == nil {
		return nil, fmt.Errorf("no connector API URL resolved for message bus application with id: %s", mb.applicationID)
	}

	return mb, nil
}

func (m *MessageBus) listConnectors() ([]interface{}, error) {
	params := map[string]interface{}{}
	if m.applicationID != nil && *m.applicationID != uuid.Nil {
		params["application_id"] = m.applicationID
	}
	status, resp, err := ListConnectors(m.token, params)
	if err != nil {
		log.Warningf("failed to retrieve connectors list; %s", err.Error())
		return nil, err
	}
	if status != 200 {
		msg := fmt.Sprintf("failed to retrieve connectors list; received status: %d", status)
		log.Warning(msg)
		return nil, errors.New(msg)
	}
	return resp.([]interface{}), nil
}

func (m *MessageBus) listContracts() ([]interface{}, error) {
	params := map[string]interface{}{}
	if m.applicationID != nil && *m.applicationID != uuid.Nil {
		params["application_id"] = m.applicationID
	}
	status, resp, err := ListContracts(m.token, params)
	if err != nil {
		log.Warningf("failed to retrieve contracts list; %s", err.Error())
		return nil, err
	}
	if status != 200 {
		msg := fmt.Sprintf("failed to retrieve contracts list; received status: %d", status)
		log.Warning(msg)
		return nil, errors.New(msg)
	}
	return resp.([]interface{}), nil
}

// Cat a messages using the given hash
func (m *MessageBus) Cat(hash string) ([]byte, error) {
	sh := shell.NewShell(*m.connectorAPIURL)
	r, err := sh.Cat(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to cat message with hash: %s; message bus id: %s; %s", hash, m.applicationID, err.Error())
	}

	defer r.Close()
	msg, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to cat message with hash: %s; message bus id: %s; %s", hash, m.applicationID, err.Error())
	}
	log.Debugf("read %d-byte message from IPFS; hash: %s", len(msg), hash)

	return msg, nil
}

// CatWrapped cats a directory-wrapped object given the directory hash
func (m *MessageBus) CatWrapped(hash string) ([]byte, error) {
	entities, err := m.Ls(hash)
	if err != nil {
		return nil, err
	}
	if len(entities) != 1 {
		return nil, fmt.Errorf("expected wraped directory to contain a single entity; contained %d", len(entities))
	}
	return m.Cat(entities[0].Hash)
}

// Ls lists messages in the directory pointed to by the given hash
func (m *MessageBus) Ls(hash string) ([]*shell.LsLink, error) {
	sh := shell.NewShell(*m.connectorAPIURL)
	return sh.List(hash)
}

// ListMessages returns a list of messages from the on-chain registry
func (m *MessageBus) ListMessages() ([]interface{}, error) {
	status, resp, err := ExecuteContract(m.token, m.contractID.String(), map[string]interface{}{
		"method":         "listMessages",
		"params":         []int{1, defaultMessagesPerPage},
		"value":          0,
		"account_address": m.accountAddress,
	})
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("failed to retrieve messages in registry contract; status: %d; response: %s", status, resp)
	}
	if response, ok := resp.(map[string]interface{}); ok {
		if messages, messagesOk := response["response"].([]interface{}); messagesOk {
			return messages, nil
		}
	}
	return nil, fmt.Errorf("retrieved non-array response when listing messages in registry contract; response: %s", resp)
}

func (m *MessageBus) resolveApplication() error {
	params := map[string]interface{}{}
	status, resp, err := GetApplicationDetails(m.token, m.applicationID.String(), params)
	if err != nil {
		return fmt.Errorf("failed to retrieve details for application with id: %s; %s", m.applicationID, err.Error())
	}
	if status != 200 {
		return fmt.Errorf("failed to retrieve details for application with id: %s; %s", m.applicationID, resp)
	}
	m.application = resp.(map[string]interface{})
	appID, _ := resp.(map[string]interface{})["id"].(string)
	applicationID, _ := uuid.FromString(appID)
	m.applicationID = &applicationID
	return nil
}

func (m *MessageBus) resolveConnector() error {
	connectors, err := m.listConnectors()
	if err != nil {
		return fmt.Errorf("no connectors resolved for message bus application with id: %s; %s", m.applicationID, err.Error())
	}
	if connectors == nil || len(connectors) == 0 {
		return fmt.Errorf("no connectors resolved for message bus application with id: %s", m.applicationID)

	}
	for _, c := range connectors {
		cnnectorID, _ := c.(map[string]interface{})["id"].(string)
		cnnector := c.(map[string]interface{})
		if cnnector["type"] == connectorTypeIPFS {
			m.connector = cnnector
			connectorID, _ := uuid.FromString(cnnectorID)
			m.connectorID = &connectorID
			break
		}
	}

	if m.connector == nil {
		return fmt.Errorf("no IPFS connector resolved for message bus application with id %s", m.applicationID)
	}
	return nil
}

func (m *MessageBus) resolveContract() error {
	contracts, err := m.listContracts()
	if err != nil {
		return fmt.Errorf("no contracts resolved for message bus application with id: %s; %s", m.applicationID, err.Error())
	}
	if contracts == nil || len(contracts) == 0 {
		return fmt.Errorf("no contracts resolved for message bus application with id: %s", m.applicationID)

	}
	for _, c := range contracts {
		cntractID := c.(map[string]interface{})["id"].(string)
		status, resp, _ := GetContractDetails(m.token, cntractID, map[string]interface{}{})
		if status == 200 && resp != nil {
			contract := resp.(map[string]interface{})
			if params, paramsOk := contract["params"].(map[string]interface{}); paramsOk {
				if params["type"] == contractTypeRegistry {
					m.contract = contract
					contractID, _ := uuid.FromString(cntractID)
					m.contractID = &contractID
					break
				}
			}
		}
	}

	if m.contract == nil {
		return fmt.Errorf("no registry contract resolved for message bus application with id %s", m.applicationID)
	}

	return nil
}

// Publish the given message on the specified subject
func (m *MessageBus) Publish(subject string, msg []byte) error {
	sh := shell.NewShell(*m.connectorAPIURL)
	hash, err := sh.Add(strings.NewReader(string(msg)))
	if err != nil {
		return fmt.Errorf("failed to publish %d-byte message via message bus application: %s; %s", len(msg), m.applicationID, err.Error())

	}
	log.Debugf("published %d-byte message to IPFS; hash: %s", len(msg), hash)

	status, _, err := ExecuteContract(m.token, m.contractID.String(), map[string]interface{}{
		"method":         publishContractMethod,
		"params":         []interface{}{subject, hash},
		"value":          0,
		"account_address": m.accountAddress,
	})
	if err != nil {
		return fmt.Errorf("failed to execute publish method on message bus application registry contract with id: %s; %s", m.contractID, err.Error())
	}
	if status != 202 {
		return fmt.Errorf("failed to execute publish method on message bus application registry contract with id: %s; status: %d", m.contractID, status)
	}

	return nil
}
