package webext

import (
	"crypto/sha512"
	"time"

	"github.com/AspieSoft/go-regex-re2/v2"
	"github.com/AspieSoft/goutil/crypt"
	"github.com/AspieSoft/goutil/syncmap"
	"github.com/AspieSoft/goutil/v7"
	"github.com/gofiber/fiber/v2"
)

// FormAuth is used to return possible options for 2 step authentication.
//
// @Enabled: True if a user has enabled 2 step authentication.
// False to skip 2auth.
//
// @Email: The email address of the user to send an authentication code to.
type FormAuth struct {
	Enabled bool

	Email string
}

type formSessionData struct {
	pcid string
	cookie string
	exp time.Time
}

var formSession *syncmap.SyncMap[string, formSessionData] = syncmap.NewMap[string, formSessionData]()

// GetPCID is a method you can override.
//
// This method should return a unique identifier of the users ip and browser, and
// the result needs to be connsistantly the same even between sessions.
//
// This ID is used as a secondary way to verify if a session token is valid, and
// the goal is to verify that the token is being used by the same machine it was generated for.
// This can help protect users from cookie injection. A hacker would have to know all the info
// about the user this string returns.
//
// This string should only be stored server side, and never sent to the client.
//
// By default, this returns a hash of the users IP Address (RemoteAddr) and UserAgent.
var GetPCID func(c *fiber.Ctx) string = func(c *fiber.Ctx) string {
	id := sha512.Sum512([]byte(c.Context().RemoteAddr().String()+"@"+string(c.Context().UserAgent())))
	return string(id[:])
}

// FormVerifyLogin is a method you can override.
// It is necessary to create this function if you intend to use the VerifyLogin middleware.
//
// This method should check your database and verify if a username and password is valid.
//
// @return
//
// @auth2: Returns a FormAuth struct which is used to determine what 2 step authentication
// methods the user can accept. It should also include `Enabled: true|false` to specify if
// a user has 2auth enabled or disabled.
//
// @verified: Should return true if the username and password are correct and valid. Return
// false to reject the login and return an `Invalid Username or Password` error.
//
// Notice: The 2auth method is still in development, and is not currently available.
// It is recommended for the first argument, you should simply pass `FormmAuth{Enabled: false}`.
var FormVerifyLogin func(username string, password string) (auth2 FormAuth, verified bool) = func (username string, password string) (FormAuth, bool) {
	// verify user in database
	return FormAuth{Enabled: false}, false
}

// FormVerifyLoginSession is a method you can override.
// It is necessary to create this function if you intend to use the VerifyLogin middleware.
//
// This method should check your database for a session token verifying if the users
// login_session cookie is valid and not expired.
var FormVerifyLoginSession func(token string) (verified bool) = func (token string) bool {
	// verify user session in database
	return false
}

// FormCreateLoginSession is a method you can override.
// It is necessary to create this function if you intend to use the VerifyLogin middleware.
//
// This method runs after the login has been successfully verified.
//
// You need to generate a unique random token and
//  - store it in your database
//  - return the same token as the first argument of this function
//
// The second argument should return when that token should expire.
// The token will be sent to the user as a login_session cookie.
// It is also highly recommended you store the expiration of the token in your database.
var FormCreateLoginSession func() (token string, exp time.Time) = func() (string, time.Time) {
	// add user session to database
	return string(crypt.RandBytes(256)), time.Now().Add(-24 * time.Hour) // expire now
}

// FormRemoveLoginSession is a method you can override.
// It is necessary to create this function if you intend to use the VerifyLogin middleware.
//
// This method is called when a user logs out.
//
// You need to remove the login_session token from your database.
// The cookie will automatically be cleared.
//
// It is highly recommended you do Not keep the now invalid token in your database
// for security. If the user logged out, we do not want to keep any unused tokens
// for a hacker to try and abuse.
var FormRemoveLoginSession func(token string) = func(token string) {
	// remove user session from database
}


//todo: add middleware for verifying user login or return a login form
// also allow the admin to specify the layout of the login form
// add support for 2auth through email or an authenticator app
// have admin specify a custom email sending callback
// add optional "sign in with XXXX" option


// VerifyLogin will verify if a user is loggedin
// or present them with a login form on GET requests.
//
// Note: POST requests will return a 401 error if the user is not loggedin.
//
// Notice: This method is still in development and is experimental.
// Use at your own risk.
func VerifyLogin() func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		hostname := string(regex.Comp(`:[0-9]+$`).RepStrLit([]byte(goutil.Clean.Str(c.Hostname())), []byte{}))
		path := goutil.Clean.Str(c.Path())

		action := goutil.Clean.Str(c.FormValue("action"))

		var formStatus int = 200
		var formError string

		if action == "logout" {
			formToken := goutil.Clean.Str(c.FormValue("session"))
			FormRemoveLoginSession(formToken)
			c.ClearCookie("login_session")
		}else if action == "login" {
			//todo: add login method and limit attempts
			// also verify session

			formToken := goutil.Clean.Str(c.FormValue("session"))
			if session, ok := formSession.Get(formToken); ok && session.pcid == GetPCID(c) && time.Now().UnixMilli() < session.exp.UnixMilli() {
				formSession.Del(formToken)
				if formCookie := goutil.Clean.Str(c.Cookies("form_session")); formCookie == session.cookie {
					c.ClearCookie("form_session")

					if auth2, ok := FormVerifyLogin(goutil.Clean.Str(c.FormValue("username")), goutil.Clean.Str(c.FormValue("password"))); ok {
						if !auth2.Enabled || true /* temp: 2auth under development */ /* todo: verify if a 2auth method is handled by the admin and is not nil */ {
							loginToken, exp := FormCreateLoginSession()

							c.Cookie(&fiber.Cookie{
								Name: "login_session",
								Value: loginToken,
								Expires: exp,
								Path: "/",
								Domain: hostname,
								Secure: true,
								HTTPOnly: true,
								SameSite: "Strict",
							})

							return c.Next()
						}

						//todo: handle 2auth form
					}

					formStatus = 401
					formError = "Incorrect Username Or Password!"
				}
			}

			formStatus = 408
			formError = "Session Invalid Or Expired!"
		}

		loginToken := goutil.Clean.Str(c.Cookies("login_session"))
		if loginToken != "" && FormVerifyLoginSession(loginToken) {
			return c.Next()
		}

		// return error if not GET method
		if c.Method() != "GET" {
			if formStatus == 200 {
				formStatus = 401
			}

			if formError == "" {
				formError = "Authentication Required!"
			}

			c.SendStatus(formStatus)
			return c.SendString(formError)
		}

		formToken := string(crypt.RandBytes(64))
		formCookie := string(crypt.RandBytes(64))
		exp := time.Now().Add(2 * time.Hour)

		formSession.Set(formToken, formSessionData{
			pcid: GetPCID(c),
			cookie: formCookie,
			exp: exp,
		})

		c.Cookie(&fiber.Cookie{
			Name: "form_session",
			Value: formCookie,
			Expires: exp,
			Path: path,
			Domain: hostname,
			Secure: true,
			HTTPOnly: true,
			SameSite: "Strict",
		})

		return RenderPage(c, "form:login", formStatus, map[string]any{
			"session": formToken,
			"error": formError,
		})
	}
}
