package api

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/provideservices/provide-go/common"
	"github.com/vincent-petithory/dataurl"
)

const defaultContentType = "application/json"
const defaultRequestTimeout = time.Second * 10

// Client is a generic base class for calling a REST API; when a token is configured on an
// Client instance it will be provided as a bearer authorization header; when a username and
// password are configured on an Client instance, they will be used for HTTP basic authorization
// but will be passed as the Authorization header instead of as part of the URL itself. When a token
// is confgiured on an Client instance, the username and password supplied for basic auth are
// currently discarded.
type Client struct {
	Host     string
	Path     string
	Scheme   string
	Token    *string
	Username *string
	Password *string
}

func (c *Client) sendRequest(method, urlString, contentType string, params map[string]interface{}) (status int, response interface{}, err error) {
	return c.sendRequestWithTLSClientConfig(method, urlString, contentType, params,
		&tls.Config{
			InsecureSkipVerify: false,
		},
	)
}

func (c *Client) sendRequestWithTLSClientConfig(method, urlString, contentType string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   tlsClientConfig,
		},
		Timeout: defaultRequestTimeout,
	}

	mthd := strings.ToUpper(method)
	reqURL, err := url.Parse(urlString)
	if err != nil {
		common.Log.Warningf("failed to parse URL for HTTP %s request: %s; %s", method, urlString, err.Error())
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

	if mthd == "POST" || mthd == "PUT" || mthd == "PATCH" {
		var payload []byte
		switch contentType {
		case "application/json":
			payload, err = json.Marshal(params)
			if err != nil {
				common.Log.Warningf("failed to marshal JSON payload for HTTP %s request: %s; %s", method, urlString, err.Error())
				return -1, nil, err
			}

		case "application/x-www-form-urlencoded":
			urlEncodedForm := url.Values{}
			for key, val := range params {
				if valStr, valOk := val.(string); valOk {
					urlEncodedForm.Add(key, valStr)
				} else {
					common.Log.Warningf("failed to marshal application/x-www-form-urlencoded parameter: %s; value was non-string", key)
				}
			}
			payload = []byte(urlEncodedForm.Encode())

		case "multipart/form-data":
			body := new(bytes.Buffer)
			writer := multipart.NewWriter(body)
			for key, val := range params {
				if valStr, valStrOk := val.(string); valStrOk {
					dURL, err := dataurl.DecodeString(valStr)
					if err == nil {
						common.Log.Debugf("parsed data url parameter: %s", key)
						part, err := writer.CreateFormFile(key, key)
						if err != nil {
							return 0, nil, err
						}
						part.Write(dURL.Data)
					} else {
						_ = writer.WriteField(key, valStr)
					}
				} else {
					common.Log.Warningf("skipping non-string value when constructing multipart/form-data request: %s", key)
				}
			}
			err = writer.Close()
			if err != nil {
				return 0, nil, err
			}
			payload = []byte(body.Bytes())

		default:
			common.Log.Warningf("attempted HTTP %s request with unsupported content type: %s; unable to marshal request body", mthd, contentType)
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
		common.Log.Warningf("failed to invoke HTTP %s request: %s; %s", method, urlString, err.Error())
		return 0, nil, err
	}

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
	default:
		reader = resp.Body
	}

	buf := new(bytes.Buffer)
	if reader != nil {
		defer reader.Close()
		buf.ReadFrom(reader)
	}

	if buf.Len() > 0 {
		contentTypeParts := strings.Split(resp.Header.Get("Content-Type"), ";")
		switch strings.ToLower(contentTypeParts[0]) {
		case "application/json":
			err = json.Unmarshal(buf.Bytes(), &response)
			if err != nil {
				return resp.StatusCode, nil, fmt.Errorf("failed to unmarshal %v-byte HTTP %s response from %s; %s", len(buf.Bytes()), method, urlString, err.Error())
			}
		default:
			// no-op
		}
	}

	common.Log.Debugf("received %v (%v-byte) response for HTTP %s request: %s", resp.StatusCode, buf.Len(), method, urlString)
	return resp.StatusCode, response, nil
}

// Get constructs and synchronously sends an API GET request
func (c *Client) Get(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("GET", url, defaultContentType, params)
}

// GetWithTLSClientConfig constructs and synchronously sends an API GET request
func (c *Client) GetWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("GET", url, defaultContentType, params, tlsClientConfig)
}

// Post constructs and synchronously sends an API POST request
func (c *Client) Post(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("POST", url, defaultContentType, params)
}

// PostWithTLSClientConfig constructs and synchronously sends an API POST request
func (c *Client) PostWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("POST", url, defaultContentType, params, tlsClientConfig)
}

// PostWWWFormURLEncoded constructs and synchronously sends an API POST request using application/x-www-form-urlencoded as the content-type
func (c *Client) PostWWWFormURLEncoded(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("POST", url, "application/x-www-form-urlencoded", params)
}

// PostWWWFormURLEncodedWithTLSClientConfig constructs and synchronously sends an API POST request using application/x-www-form-urlencoded as the content-type
func (c *Client) PostWWWFormURLEncodedWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("POST", url, "application/x-www-form-urlencoded", params, tlsClientConfig)
}

// PostMultipartFormData constructs and synchronously sends an API POST request using multipart/form-data as the content-type
func (c *Client) PostMultipartFormData(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("POST", url, "multipart/form-data", params)
}

// PostMultipartFormDataWithTLSClientConfig constructs and synchronously sends an API POST request using multipart/form-data as the content-type
func (c *Client) PostMultipartFormDataWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("POST", url, "multipart/form-data", params, tlsClientConfig)
}

// Put constructs and synchronously sends an API PUT request
func (c *Client) Put(uri string, params map[string]interface{}) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("PUT", url, defaultContentType, params)
}

// PutWithTLSClientConfig constructs and synchronously sends an API PUT request
func (c *Client) PutWithTLSClientConfig(uri string, params map[string]interface{}, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("PUT", url, defaultContentType, params, tlsClientConfig)
}

// Delete constructs and synchronously sends an API DELETE request
func (c *Client) Delete(uri string) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequest("DELETE", url, defaultContentType, nil)
}

// DeleteWithTLSClientConfig constructs and synchronously sends an API DELETE request
func (c *Client) DeleteWithTLSClientConfig(uri string, tlsClientConfig *tls.Config) (status int, response interface{}, err error) {
	url := c.buildURL(uri)
	return c.sendRequestWithTLSClientConfig("DELETE", url, defaultContentType, nil, tlsClientConfig)
}

func (c *Client) buildURL(uri string) string {
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
