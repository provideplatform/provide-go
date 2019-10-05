package provide

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	uuid "github.com/kthomas/go.uuid"
)

const authorizationHeader = "authorization"
const defaultResponseContentType = "application/json; charset=UTF-8"
const defaultResultsPerPage = 25

// AuthorizedSubjectID returns the requested JWT subject if it matches
func AuthorizedSubjectID(c *gin.Context, subject string) *uuid.UUID {
	token, err := ParseBearerAuthorizationHeader(c, nil)
	if err != nil {
		log.Warningf("Failed to parse %s subject from bearer authorization header; %s", subject, err.Error())
		return nil
	}
	var id string
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if sub, subok := claims["sub"].(string); subok {
			subprts := strings.Split(sub, ":")
			if len(subprts) != 2 {
				log.Warningf("Failed to parse %s subject from bearer authorization header; JWT subject malformed: %s", subject, sub)
				return nil
			}
			if subprts[0] != subject {
				return nil
			}
			id = subprts[1]
		}
	}
	uuidV4, err := uuid.FromString(id)
	if err != nil {
		log.Warningf("Failed to parse %s subject from bearer authorization header; %s", subject, err.Error())
		return nil
	}
	return &uuidV4
}

// CORSMiddleware is a working middlware for using CORS with gin
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Accept, Accept-Encoding, Authorization, Cache-Control, Content-Length, Content-Type, Origin, User-Agent, X-CSRF-Token, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "X-Total-Results-Count")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// Paginate the current request given the page number and results per page;
// returns the modified SQL query and adds x-total-results-count header to
// the response
func Paginate(c *gin.Context, db *gorm.DB, model interface{}) *gorm.DB {
	page := int64(1)
	rpp := int64(defaultResultsPerPage)
	if c.Query("page") != "" {
		if _page, err := strconv.ParseInt(c.Query("page"), 10, 8); err == nil {
			page = _page
		}
	}
	if c.Query("rpp") != "" {
		if _rpp, err := strconv.ParseInt(c.Query("rpp"), 10, 8); err == nil {
			rpp = _rpp
		}
	}
	query, totalResults := paginate(db, model, page, rpp)
	if totalResults != nil {
		c.Header("x-total-results-count", fmt.Sprintf("%d", *totalResults))
	}
	return query
}

// ParseBearerAuthorizationHeader parses a bearer authorization header
// expecting to find a valid JWT token; returns the token if present
func ParseBearerAuthorizationHeader(c *gin.Context, keyfunc *func(_jwtToken *jwt.Token) (interface{}, error)) (*jwt.Token, error) {
	authorization := c.GetHeader(authorizationHeader)
	if authorization == "" {
		return nil, errors.New("No authentication header provided")
	}
	hdrprts := strings.Split(authorization, "bearer ")
	if len(hdrprts) != 2 {
		return nil, fmt.Errorf("Failed to parse bearer authentication header: %s", authorization)
	}
	authorization = hdrprts[1]
	jwtToken, err := jwt.Parse(authorization, func(_jwtToken *jwt.Token) (interface{}, error) {
		if keyfunc != nil {
			fn := *keyfunc
			return fn(_jwtToken)
		}
		if _, ok := _jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Failed to parse bearer authentication header; unexpected JWT signing alg: %s", _jwtToken.Method.Alg())
		}
		if jwtPublicKey != nil {
			return jwtPublicKey, nil
		}
		return nil, nil
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to parse bearer authentication header as valid JWT; %s", err.Error())
	}
	return jwtToken, err
}

// Render an object and status using the given gin context
func Render(obj interface{}, status int, c *gin.Context) {
	c.Header("content-type", defaultResponseContentType)
	c.Writer.WriteHeader(status)
	if &obj != nil && status != http.StatusNoContent {
		encoder := json.NewEncoder(c.Writer)
		encoder.SetIndent("", "    ")
		if err := encoder.Encode(obj); err != nil {
			panic(err)
		}
	} else {
		c.Header("content-length", "0")
	}
}

// RenderError writes an error message and status using the given gin context
func RenderError(message string, status int, c *gin.Context) {
	err := map[string]*string{}
	err["message"] = &message
	Render(err, status, c)
}

// RequireParams renders an error if any of the given parameters are not present in the given gin context
func RequireParams(requiredParams []string, c *gin.Context) error {
	var errs []string
	for _, param := range requiredParams {
		if c.Query(param) == "" {
			errs = append(errs, param)
		}
	}
	if len(errs) > 0 {
		msg := strings.Trim(fmt.Sprintf("missing required parameters: %s", strings.Join(errs, ", ")), " ")
		RenderError(msg, 400, c)
		return errors.New(msg)
	}
	return nil
}

// TrackAPICalls returns gin middleware for tracking API calls
func TrackAPICalls() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer trackAPICall(c)
		c.Next()
	}
}
