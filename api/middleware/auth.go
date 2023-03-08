package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/lefi7z/crick/api/models"
	"github.com/lefi7z/crick/api/config"
	"github.com/auth0-community/go-auth0"
	"github.com/julienschmidt/httprouter"
	"gopkg.in/square/go-jose.v2"
)

var (
	// Below are the error messages for the AuthWithToken() middleware.

	// DetailInvalidAuthorizationHeader is the error message used when the
	// Authorization header content is not valid.
	DetailInvalidAuthorizationHeader = "Invalid or missing Authorization header"
	// DetailUserNotFound is the error message used when the user is unknown.
	// Such an error can only happen with the AuthWithToken() middleware.
	DetailUserNotFound = "User not found"

	// Below are the error messages for the AuthWithAuth0() middleware.

	// DetailMalformedToken is the error message when retrieving claims from
	// the JWT token has failed.
	DetailMalformedToken = "Malformed JWT token (claims)"
	// DetailUserCreationFailed is the error message when creating a user in
	// database has failed.
	DetailUserCreationFailed = "User creation failed"
	// DetailUserSelectionFailed is the error message when fetching a user in
	// database has failed.
	DetailUserSelectionFailed = "User selection failed"
	// DetailUserProfileRetrievalFailed is the error message when getting the
	// user's profile from Auth0 API has failed.
	DetailUserProfileRetrievalFailed = "User profile retrieval failed"
)

// AuthWithAuth0 returns the Auth0 authentication middleware.
//
// This middleware expects a RS256-compliant JSON Web Token to authenticate
// users. It MUST be used to secure all handlers related to the Web
// application. The user's auth0_id should be in the "sub" claim of this token,
// according to Auth0. The JWT must be passed in the Authorization header:
//
//   Authorization: Bearer <JWT goes here>
//
// When a new user authenticates (i.e. with a auth_id not in database), this
// middleware first creates the user. In order to create the user in database,
// a call to the Auth0 API is needed to fetch basic user information.
//
// Once the user has been found (either just created or retrieved in the
// database), the middleware adds it to the request's context. Handlers must
// use the GetCurrentUser() function, and not access the context directly.
func AuthWithAuth0(h httprouter.Handle, repo models.Repository, logger *zap.Logger) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		c := config.Auth0()
		configuration := auth0.NewConfiguration(
			auth0.NewJWKClient(auth0.JWKClientOptions{URI: c.JwksURI}),
			c.Audience,
			c.Domain,
			jose.RS256,
		)
		validator := auth0.NewValidator(configuration)

		token, err := validator.ValidateRequest(r)
		if err != nil {
			logger.Warn("authentication failed", zap.Error(err))
			SendError(w, http.StatusUnauthorized, DetailUserNotFound)
			return
		}

		// user's auth0_id is stored in a JWT claim (`sub`)
		claims := map[string]interface{}{}
		err = validator.Claims(r, token, &claims)
		if err != nil {
			logger.Warn("cannot retrieve JWT claims", zap.Error(err))
			SendError(w, http.StatusBadRequest, DetailMalformedToken)
			return
		}

		id := claims["sub"].(string)

		u, err := repo.GetUserByAuth0ID(id)
		if err != nil {
			if err == sql.ErrNoRows {
				logger.Info(
					"create new authenticated user",
					zap.String("auth0_id", id),
					zap.String("login", claims["nickname"].(string)),
					zap.String("avatar_url", claims["picture"].(string)),
				)
				u, err = repo.CreateNewUser(id,
					claims["nickname"].(string),
					claims["picture"].(string))
				if err != nil {
					logger.Error("cannot create new user", zap.Error(err))
					SendError(w, http.StatusInternalServerError, DetailUserCreationFailed)
					return
				}
			} else {
				logger.Error("could not select user by ID", zap.Error(err), zap.String("auth0_id", id))
				SendError(w, http.StatusInternalServerError, DetailUserSelectionFailed)
				return
			}
		}

		ctx := context.WithValue(r.Context(), ContextCurrentUser, u)
		h(w, r.WithContext(ctx), ps)
	}
}

// AuthWithToken returns the token-based middleware.
//
// This middleware expects an API token in the Authorization header as follows:
//
//   Authorization: Token <API token goes here>
//
// Once the user has been found, the middleware adds it to the request's
// context. Handlers must use the GetCurrentUser() function, and not access the
// context directly.
func AuthWithToken(h httprouter.Handle, repo models.Repository, logger *zap.Logger) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		auth := r.Header.Get("Authorization")
		token := strings.TrimPrefix(auth, "Token ")
		if token == "" {
			logger.Warn("bad authorization header", zap.String("authorization_header", auth))
			SendError(w, http.StatusBadRequest, DetailInvalidAuthorizationHeader)
			return
		}

		u, err := repo.GetUserByToken(token)
		if err != nil {
			logger.Warn("get user by token", zap.Error(err))
			SendError(w, http.StatusUnauthorized, DetailUserNotFound)
			return
		}

		ctx := context.WithValue(r.Context(), ContextCurrentUser, u)
		h(w, r.WithContext(ctx), ps)
	}
}

