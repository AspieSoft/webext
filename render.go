package webext

import "github.com/gofiber/fiber/v2"

// StatusError is an http status error
type StatusError struct {
	status int
	msg string
}

// NewStatusError returns a new status error
func NewStatusError(status int, msg string) *StatusError {
	return &StatusError{status: status, msg: msg}
}

// Status returns the status error code
func (statusError *StatusError) Status() int {
	return statusError.status
}

// Msg returns the status error message
func (statusError *StatusError) Msg() string {
	return statusError.msg
}

// RenderPage is a method you can override.
//
// It is used to handle page rendering.
// You can decide how you want to handle pages here.
// You can also setup a templating engine of your choice with this method.
var RenderPage func(c *fiber.Ctx, url string, status int, args map[string]any) error = func(c *fiber.Ctx, url string, status int, args map[string]any) error {
	//todo: handle page rendering
	c.SendStatus(500)
	return c.SendString("Render Page Handler Needs Setup")
}

// RenderError is a method you can override.
//
// It is used to handle http errors.
// You can decide how you want to handle rendering http errors here.
// You can also setup a templating engine of your choice with this method.
var RenderError func(c *fiber.Ctx, url string, statusError *StatusError, args map[string]any) error = func(c *fiber.Ctx, url string, statusError *StatusError, args map[string]any) error {
	if statusError != nil {
		c.SendStatus(statusError.status)
		return c.SendString(statusError.msg)
	}
	return nil
}
