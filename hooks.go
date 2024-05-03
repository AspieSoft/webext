package webext

import "time"

type hookList struct {
	// LoginForm contains hooks for verifying and handling the login middleware.
	// You should set the methods of these hooks to interact with your database.
	LoginForm struct {
		// VerifyUserPass is a method you can override.
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
		VerifyUserPass func(username string, password string) (uuid string, auth2 FormAuth, verified bool)

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
		CreateSession func(uuid string) (token string, exp time.Time, err *StatusError)

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
	}
}

// Functions that you should override to handle database interaction and
// other methods that may be called within the module.
var Hooks hookList = hookList{}
