package provide

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIClient is the base class for calling a provide microservice
type APIClient struct {
	Host   string
	Path   string
	Scheme string
	Token  *string
}

func (c *APIClient) sendRequest(method, urlString string, params map[string]interface{}) (status int, response interface{}, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		Timeout: time.Second * 30,
	}

	mthd := strings.ToUpper(method)
	reqURL, err := url.Parse(urlString)
	if err != nil {
		Log.Warningf("Failed to parse URL for provide API (%s %s) invocation; %s", method, urlString, err.Error())
		return -1, nil, err
	}

	if mthd == "GET" && params != nil {
		q := reqURL.Query()
		for name := range params {
			if val, valOk := params[name].(string); valOk {
				q.Set(name, val)
			}
		}
		reqURL.RawQuery = q.Encode()
	}

	headers := map[string][]string{
		"Accept-Encoding": {"gzip, deflate"},
		"Accept-Language": {"en-us"},
		"Accept":          {"application/json"},
	}
	if c.Token != nil {
		headers["Authorization"] = []string{fmt.Sprintf("bearer %s", *c.Token)}
	}

	var req *http.Request

	if mthd == "POST" || mthd == "PUT" {
		payload, err := json.Marshal(params)
		if err != nil {
			Log.Warningf("Failed to marshal JSON payload for provide API (%s %s) invocation; %s", method, urlString, err.Error())
			return -1, nil, err
		}
		req, _ = http.NewRequest(method, urlString, bytes.NewReader(payload))
		headers["Content-Type"] = []string{"application/json"}
	} else {
		req = &http.Request{
			URL:    reqURL,
			Method: mthd,
		}
	}

	req.Header = headers

	resp, err := client.Do(req)
	Log.Debugf("Received %v response for provide API (%s %s) invocation", resp.StatusCode, method, urlString)

	if err != nil {
		Log.Warningf("Failed to invoke provide API (%s %s) method: %s; %s", method, urlString, err.Error())
		return 0, nil, err
	}

	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	err = json.Unmarshal(buf.Bytes(), &response)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("Failed to unmarshal provide API (%s %s) response: %s; %s", method, urlString, buf.Bytes(), err.Error())
	}

	Log.Debugf("Invocation of provide API (%s %s) succeeded (%v-byte response)", method, urlString, buf.Len())
	return resp.StatusCode, response, nil
}

func (c *APIClient) get(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("GET", url, params)
}

func (c *APIClient) post(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("POST", url, params)
}

func (c *APIClient) put(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("PUT", url, params)
}

func (c *APIClient) delete(uri string) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("DELETE", url, nil)
}

func (c *APIClient) buildURL(uri string) string {
	return fmt.Sprintf("%s://%s/%s/%s", c.Scheme, c.Host, c.Path, uri)
}
