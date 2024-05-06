package webext

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

type hookList struct {
	// LoginForm contains hooks for verifying and handling the login middleware.
	// You should set the methods of these hooks to interact with your database.
	LoginForm hookListLoginForm

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
	GetPCID func(c *fiber.Ctx) string
}

type hookListLoginForm struct {
	// VerifyUserPass is a method you can override.
	// It is necessary to create this function if you intend to use the VerifyLogin middleware.
	//
	// This method should check your database and verify if a username and password is valid.
	//
	// @return
	//
	// @uuid: a unique user id that will be added to c.Locals("uuid")
	//
	// @verified: Should return true if the username and password are correct and valid. Return
	// false to reject the login and return an `Invalid Username or Password` error.
	VerifyUserPass func(username string, password string) (uuid string, verified bool)

	// VerifySession is a method you can override.
	// It is necessary to create this function if you intend to use the VerifyLogin middleware.
	//
	// This method should check your database for a session token verifying if the users
	// login_session cookie is valid and not expired.
	VerifySession func(token string) (uuid string, verified bool)

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
	CreateSession func(uuid string) (token string, exp time.Time, err error)

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
	RemoveSession func(token string)

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
	// Note: We assume that your login form will likely be using ajax requests to the same path as the form.
	// Every other value returns strings and http status codes, and not html.
	Render func(c *fiber.Ctx, session string) error

	// OnAttempt is a method you can override.
	// It is necessary to create this function if you intend to use the VerifyLogin middleware.
	//
	// This method will be called before a login attempt.
	// It should be paired with the OnFailedAttempt method, to prevent a login attempt if there were too many.
	//
	// @method: the type of login method that is being checked
	//  - "password" // username and password
	//  - "2auth" // 2 step authentication
	//  - "0auth" // sign in with google, apple, etc. (Note: 0auth not yet available)
	//
	// @allow: return true to allow a login attempt.
	// return false to deny a login attempt.
	OnAttempt func(c *fiber.Ctx, method string) (allow bool)

	// OnFailedAttempt is a method you can override.
	// It is necessary to create this function if you intend to use the VerifyLogin middleware.
	//
	// This method will be called when a login attempt fails.
	// For security, you should setup a limiter to failed login attempts.
	//
	// @method: the type of login method that failed
	//  - "password" // incurrect username or password
	//  - "2auth" // failed 2 step authentication
	//  - "0auth" // failed sign in with google, apple, etc. (Note: 0auth not yet available)
	OnFailedAttempt func(c *fiber.Ctx, method string)

	// Has2Auth is a method you can override.
	// This method is optional, and will be called to verify if a user should be send a 2auth from.
	//
	// return true if the current user has a 2auth method.
	// return false if the 2auth method should be skipped,
	// and the user should be logged in with just the username and password.
	//
	// Note: this method also requires the Render2Auth and Verify2Auth methods.
	Has2Auth func(uuid string) bool

	// Render2Auth is a method you can override.
	// This method is optional, and will be called to render a 2 step authentication form.
	//
	// It is recommended you add this method for security.
	//
	// @session is a session token you need to add to the form.
	//  <input type="hidden" name="session" value="{{session}}"/>
	//
	// You should also add the action "login" to the form to trigger the login action.
	//  <input type="hidden" name="action" value="login_2auth"/>
	//
	// Note: We assume you will handle 2auth methods and verification on your own.
	// There are many different ways of doing 2auth, so adding all of them is not possible.
	// We also assume you will likely be using ajax requests to the same path as the form.
	//
	// Note: this method also requires the Has2ARender2Authuth and Verify2Auth methods.
	Render2Auth func(c *fiber.Ctx, uuid string, session string) error

	// Verify2Auth is a method you can override.
	// This method is optional, and will be called to verify if a 2auth method was successfully verified.
	//
	// @return
	//
	// @uuid: a unique user id that will be added to c.Locals("uuid")
	//
	// @verified: Should return true if the username and password are correct and valid. Return
	// false to reject the login and return an `Invalid Username or Password` error.
	//
	// Note: this method also requires the Has2Auth and Render2Auth methods.
	Verify2Auth func(c *fiber.Ctx) (uuid string, verified bool)

	// OnLogin is a method you can add/append a callback to.
	// This method is optional, and will be called imidiatelly after a successful login attempt
	//
	// @uuid: the users uuid you can use as a database reference.
	//
	// @return
	//
	// @allowLogin: return nill to allow the login to pass authentication.
	// return an error to deny the login attempt (incase you want an attitional layer of security).
	OnLogin []func(uuid string) (allowLogin error)
}

// Functions that you should override to handle database interaction and
// other methods that may be called within the module.
var Hooks hookList = hookList{
	LoginForm: hookListLoginForm{
		OnLogin: []func(uuid string) (allowLogin error){},
	},
}
