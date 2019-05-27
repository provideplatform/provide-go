package provide

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultContentType = "application/json"

// APIClient is a generic base class for calling a REST API; when a token is configured on an
// APIClient instance it will be provided as a bearer authorization header; when a username and
// password are configured on an APIClient instance, they will be used for HTTP basic authorization
// but will be passed as the Authorization header instead of as part of the URL itself. When a token
// is confgiured on an APIClient instance, the username and password supplied for basic auth are
// currently discarded.
type APIClient struct {
	Host     string
	Path     string
	Scheme   string
	Token    *string
	Username *string
	Password *string
}

func (c *APIClient) sendRequest(method, urlString, contentType string, params map[string]interface{}) (status int, response interface{}, err error) {
	return c.sendRequestWithTLSClientConfig(method, urlString, contentType, params,
		&tls.Config{
			InsecureSkipVerify: false,
		},
	)
}

func (c *APIClient) sendRequestWithTLSClientConfig(method, urlString, contentType string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   tlsClientConfig,
		},
		Timeout: time.Second * 30,
	}

	mthd := strings.ToUpper(method)
	reqURL, err := url.Parse(urlString)
	if err != nil {
		Log.Warningf("Failed to parse URL for HTTP %s request; URL: %s; %s", method, urlString, err.Error())
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
	} else if c.Username != nil && c.Password != nil {
		headers["Authorization"] = []string{buildBasicAuthorizationHeader(*c.Username, *c.Password)}
	}

	var req *http.Request

	if mthd == "POST" || mthd == "PUT" {
		var payload []byte
		if contentType == "application/json" {
			payload, err = json.Marshal(params)
			if err != nil {
				Log.Warningf("Failed to marshal JSON payload for HTTP %s request; URL: %s; invocation; %s", method, urlString, err.Error())
				return -1, nil, err
			}
		} else if contentType == "application/x-www-form-urlencoded" {
			urlEncodedForm := url.Values{}
			for key, val := range params {
				if valStr, valOk := val.(string); valOk {
					urlEncodedForm.Add(key, valStr)
				} else {
					Log.Warningf("Failed to marshal application/x-www-form-urlencoded parameter: %s; value was non-string", key)
				}
			}
			payload = []byte(urlEncodedForm.Encode())
		}

		req, _ = http.NewRequest(method, urlString, bytes.NewReader(payload))
		headers["Content-Type"] = []string{contentType}
	} else {
		req = &http.Request{
			URL:    reqURL,
			Method: mthd,
		}
	}

	req.Header = headers

	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		Log.Warningf("Failed to invoke HTTP %s request; URL: %s; %s", method, urlString, err.Error())
		return 0, nil, err
	}

	Log.Debugf("Received %v response for HTTP %s request (%v-byte response received); URL: %s", resp.StatusCode, method, urlString)

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		defer reader.Close()
	default:
		reader = resp.Body
	}

	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	err = json.Unmarshal(buf.Bytes(), &response)
	if err != nil {
		return resp.StatusCode, nil, fmt.Errorf("Failed to unmarshal HTTP %s response; URL: %s; response: %s; %s", method, urlString, buf.Bytes(), err.Error())
	}

	Log.Debugf("Invocation of HTTP %s request succeeded (%v-byte response received); URL: %s", method, buf.Len(), urlString)
	return resp.StatusCode, response, nil
}

// Get constructs and synchronously sends an API GET request
func (c *APIClient) Get(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("GET", url, defaultContentType, params)
}

// GetWithTLSClientConfig constructs and synchronously sends an API GET request
func (c *APIClient) GetWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("GET", url, defaultContentType, params, tlsClientConfig)
}

// Post constructs and synchronously sends an API POST request
func (c *APIClient) Post(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("POST", url, defaultContentType, params)
}

// PostWithTLSClientConfig constructs and synchronously sends an API POST request
func (c *APIClient) PostWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("POST", url, defaultContentType, params, tlsClientConfig)
}

// PostWWWFormURLEncoded constructs and synchronously sends an API POST request using application/x-www-form-urlencoded as the content-type
func (c *APIClient) PostWWWFormURLEncoded(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("POST", url, "application/x-www-form-urlencoded", params)
}

// PostWWWFormURLEncodedWithTLSClientConfig constructs and synchronously sends an API POST request using application/x-www-form-urlencoded as the content-type
func (c *APIClient) PostWWWFormURLEncodedWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("POST", url, "application/x-www-form-urlencoded", params, tlsClientConfig)
}

// Put constructs and synchronously sends an API PUT request
func (c *APIClient) Put(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("PUT", url, defaultContentType, params)
}

// PutWithTLSClientConfig constructs and synchronously sends an API PUT request
func (c *APIClient) PutWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("PUT", url, defaultContentType, params, tlsClientConfig)
}

// Delete constructs and synchronously sends an API DELETE request
func (c *APIClient) Delete(uri string) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("DELETE", url, defaultContentType, nil)
}

// DeleteWithTLSClientConfig constructs and synchronously sends an API DELETE request
func (c *APIClient) DeleteWithTLSClientConfig(uri string, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("DELETE", url, defaultContentType, nil, tlsClientConfig)
}

func (c *APIClient) buildURL(uri string) string {
	path := c.Path
	if len(path) == 1 && path == "/" {
		path = ""
	} else if len(path) > 1 && strings.Index(path, "/") != 0 {
		path = fmt.Sprintf("/%s", path)
	}
	return fmt.Sprintf("%s://%s%s/%s", c.Scheme, c.Host, path, uri)
}

func buildBasicAuthorizationHeader(username, password string) string {
	auth := fmt.Sprintf("%s:%s", username, password)
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(auth)))
}
