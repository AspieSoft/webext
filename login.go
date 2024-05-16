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

type formSessionData struct {
	pcid string
	cookie string
	exp time.Time
}

var formSession *syncmap.SyncMap[string, formSessionData] = syncmap.NewMap[string, formSessionData]()

func init(){
	if Hooks.GetPCID == nil {
		Hooks.GetPCID = func(c *fiber.Ctx) string {
			id := sha512.Sum512([]byte(c.Context().RemoteAddr().String()+"@"+string(c.Context().UserAgent())))
			return string(id[:])
		}
	}

	if Hooks.LoginForm.VerifyUserPass == nil {
		Hooks.LoginForm.VerifyUserPass = func(username, password string) (uuid string, verified bool) {
			// verify user in database
			return "", false
		}
	}

	if Hooks.LoginForm.VerifySession == nil {
		Hooks.LoginForm.VerifySession = func(token string) (uuid string, verified bool) {
			// verify user session in database
			return "", false
		}
	}

	if Hooks.LoginForm.CreateSession == nil {
		Hooks.LoginForm.CreateSession = func(uuid string) (token string, exp time.Time, err error) {
			// add user session to database
			return string(crypt.RandBytes(256)), time.Now().Add(-24 * time.Hour), errors.New("500:Create Session Method Needs Setup!") // expire now
		}
	}

	if Hooks.LoginForm.RemoveSession == nil {
		Hooks.LoginForm.RemoveSession = func(token string) {
			// remove user session from database
		}
	}

	if Hooks.LoginForm.Render == nil {
		Hooks.LoginForm.Render = func(c *fiber.Ctx, session string) error {
			c.Status(500)
			return c.SendString("Login Form Render Method Needs Setup!")
		}
	}

	if Hooks.LoginForm.OnAttempt == nil {
		Hooks.LoginForm.OnAttempt = func(c *fiber.Ctx, method string) (allow bool) {
			// check database for number of failed attempts
			return true
		}
	}

	if Hooks.LoginForm.OnFailedAttempt == nil {
		Hooks.LoginForm.OnFailedAttempt = func(c *fiber.Ctx, method string) {
			// add failed attempt count to database with expiration
		}
	}

	if Hooks.LoginForm.OnLogin == nil {
		Hooks.LoginForm.OnLogin = []func(uuid string) (allowLogin error){}
	}
}


//todo: add optional recaptcha to login form

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
			if ok := Hooks.LoginForm.OnAttempt(c, "password"); !ok {
				c.SendStatus(429)
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

						if Hooks.LoginForm.Has2Auth != nil && Hooks.LoginForm.Render2Auth != nil && Hooks.LoginForm.Verify2Auth != nil && Hooks.LoginForm.Has2Auth(uuid) {
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

							return Hooks.LoginForm.Render2Auth(c, uuid, formToken)
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

					Hooks.LoginForm.OnFailedAttempt(c, "password")

					c.SendStatus(401)
					return c.SendString("Incorrect Username Or Password!")
				}
			}

			c.ClearCookie("form_session")
			c.SendStatus(408)
			return c.SendString("Session Invalid Or Expired!")
		}else if action == "login_2auth" && Hooks.LoginForm.Has2Auth != nil && Hooks.LoginForm.Render2Auth != nil && Hooks.LoginForm.Verify2Auth != nil {
			if ok := Hooks.LoginForm.OnAttempt(c, "2auth"); !ok {
				c.SendStatus(429)
				return c.SendString("Too Many Login Attempts!")
			}

			formToken := goutil.Clean.Str(c.FormValue("session"))
			if session, ok := formSession.Get(formToken); ok && session.pcid == Hooks.GetPCID(c) && time.Now().UnixMilli() < session.exp.UnixMilli() {
				formSession.Del(formToken)
				if formCookie := goutil.Clean.Str(c.Cookies("form_session")); formCookie == session.cookie {
					c.ClearCookie("form_session")

					if uuid, ok := Hooks.LoginForm.Verify2Auth(c); ok {
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

					Hooks.LoginForm.OnFailedAttempt(c, "2auth")

					c.SendStatus(401)
					return c.SendString("Failed 2 Step Authentication!")
				}
			}

			c.ClearCookie("form_session")
			c.SendStatus(408)
			return c.SendString("Session Invalid Or Expired!")
		}

		//todo: add optional "login_0auth" action for sign in with google, apple, etc.

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
