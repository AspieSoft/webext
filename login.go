package webext

import (
	"crypto/sha512"
	"errors"
	"strconv"
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

func init(){
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
	Hooks.GetPCID = func(c *fiber.Ctx) string {
		id := sha512.Sum512([]byte(c.Context().RemoteAddr().String()+"@"+string(c.Context().UserAgent())))
		return string(id[:])
	}

	// VerifyUserPass is a method you can override.
	// It is necessary to create this function if you intend to use the VerifyLogin middleware.
	//
	// This method should check your database and verify if a username and password is valid.
	//
	// @return
	//
	// @verified: Should return true if the username and password are correct and valid. Return
	// false to reject the login and return an `Invalid Username or Password` error.
	//
	// Notice: The 2auth method is still in development, and is not currently available.
	// It is recommended for the first argument, you should simply pass `FormmAuth{Enabled: false}`.
	Hooks.LoginForm.VerifyUserPass = func(username, password string) (uuid string, verified bool) {
		// verify user in database
		return "", false
	}

	// VerifySession is a method you can override.
	// It is necessary to create this function if you intend to use the VerifyLogin middleware.
	//
	// This method should check your database for a session token verifying if the users
	// login_session cookie is valid and not expired.
	Hooks.LoginForm.VerifySession = func(token string) (uuid string, verified bool) {
		// verify user session in database
		return "", false
	}

	// CreateSession is a method you can override.
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
	//
	// If you cannot add the login session for any reason, return StatusError as the last argument
	// with a status code and an error message. For no error, just return nil.
	Hooks.LoginForm.CreateSession = func(uuid string) (token string, exp time.Time, err error) {
		// add user session to database
		return string(crypt.RandBytes(256)), time.Now().Add(-24 * time.Hour), errors.New("500:Create Session Method Needs Setup!") // expire now
	}

	// RemoveSession is a method you can override.
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
	Hooks.LoginForm.RemoveSession = func(token string) {
		// remove user session from database
	}

	// Render is a method you can override.
	// It is necessary to create this function if you intend to use the VerifyLogin middleware.
	//
	// This method is called when you need to render a login form for users.
	//
	// @session is a session token you need to add to the form.
	//  <input type="hidden" name="session" value="{{session}}"/>
	//
	// You should also add the action "login" to the form to trigger the login action.
	//  <input type="hidden" name="action" value="login"/>
	//
	// To trigger the logout method, simply use the action "logout" (session token not needed).
	//  <input type="hidden" name="action" value="logout"/>
	//
	// Note: we assume that your login form will likely be using ajax requests to the same path as the form.
	// Every other value returns strings and http status codes, and not html.
	Hooks.LoginForm.Render = func(c *fiber.Ctx, session string) error {
		c.Status(500)
		return c.SendString("Login Form Render Method Needs Setup!")
	}

	// OnLogin is a method you can add/append a callback to.
	// This method is optional, and will be called imidiatelly after a successful login attempt
	//
	// @uuid: the users uuid you can use as a database reference.
	//
	// @return
	//
	// @allowLogin: return nill to allow the login to pass authentication.
	// return an error to deny the login attempt (incase you want an attitional layer of security).
	Hooks.LoginForm.OnLogin = []func(uuid string) (allowLogin error){}
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
//
// If user is successfully logged in, their uuid will be returned in c.Locals("uuid")
func VerifyLogin() func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		hostname := string(regex.Comp(`:[0-9]+$`).RepStrLit([]byte(goutil.Clean.Str(c.Hostname())), []byte{}))
		path := goutil.Clean.Str(c.Path())

		action := goutil.Clean.Str(c.FormValue("action"))

		if action == "logout" {
			formToken := goutil.Clean.Str(c.FormValue("session"))
			Hooks.LoginForm.RemoveSession(formToken)
			c.ClearCookie("login_session")
		}else if action == "login" {
			//todo: add login method and limit attempts
			if ok := Hooks.LoginForm.OnAttempt(c); !ok {
				//todo: find correct status code for limiting login attempts
				c.SendStatus(401)
				return c.SendString("Too Many Login Attempts!")
			}

			formToken := goutil.Clean.Str(c.FormValue("session"))
			if session, ok := formSession.Get(formToken); ok && session.pcid == Hooks.GetPCID(c) && time.Now().UnixMilli() < session.exp.UnixMilli() {
				formSession.Del(formToken)
				if formCookie := goutil.Clean.Str(c.Cookies("form_session")); formCookie == session.cookie {
					c.ClearCookie("form_session")

					if uuid, ok := Hooks.LoginForm.VerifyUserPass(goutil.Clean.Str(c.FormValue("username")), goutil.Clean.Str(c.FormValue("password"))); ok {
						for _, cb := range Hooks.LoginForm.OnLogin {
							if err := cb(uuid); err != nil {
								c.SendStatus(401)
								return c.SendString(err.Error())
							}
						}

						loginToken, exp, loginErr := Hooks.LoginForm.CreateSession(uuid)
	
						if loginErr != nil {
							status := 401
							msg := regex.Comp(`^([0-9]+):\s*`).RepFunc([]byte(loginErr.Error()), func(data func(int) []byte) []byte {
								if i, err := strconv.Atoi(string(data(1))); err == nil {
									status = i
								}
								return []byte{}
							}, true)
							c.SendStatus(status)
							return c.Send(msg)
						}

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

						c.Locals("uuid", uuid)
						return c.Next()
					}

					Hooks.LoginForm.OnFailedAttempt(c)

					c.SendStatus(401)
					return c.SendString("Incorrect Username Or Password!")
				}
			}

			c.ClearCookie("form_session")
			c.SendStatus(408)
			return c.SendString("Session Invalid Or Expired!")
		}

		loginToken := goutil.Clean.Str(c.Cookies("login_session"))
		if loginToken != "" {
			if uuid, ok := Hooks.LoginForm.VerifySession(loginToken); ok {
				c.Locals("uuid", uuid)
				return c.Next()
			}
		}

		// return error if not GET method
		/* if c.Method() != "GET" {
			c.SendStatus(401)
			return c.SendString("Authentication Required!")
		} */

		// send user a login form
		formToken := string(crypt.RandBytes(64))
		formCookie := string(crypt.RandBytes(64))
		exp := time.Now().Add(2 * time.Hour)

		formSession.Set(formToken, formSessionData{
			pcid: Hooks.GetPCID(c),
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

		c.SendStatus(401)
		return Hooks.LoginForm.Render(c, formToken)
	}
}

// GetLoginSession will populate c.Locals("uuid") with a user uuid
// if a login session is verified.
//
// Note: Unlike the VerifyLogin middleware, this middleware will Not
// prevent c.Next() if the user is not logged in.
func GetLoginSession() func(c *fiber.Ctx) error {
	return func(c *fiber.Ctx) error {
		loginToken := goutil.Clean.Str(c.Cookies("login_session"))
		if loginToken != "" {
			if uuid, ok := Hooks.LoginForm.VerifySession(loginToken); ok {
				c.Locals("uuid", uuid)
			}
		}

		return c.Next()
	}
}
