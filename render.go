package webext

import "github.com/gofiber/fiber/v2"

type StatusError struct {
	status int
	msg string
}

// RenderPage is a method you can override.
//
// It is used to handle page rendering.
// You can decide how you want to handle pages and errors here.
// You can also setup a templating engine of your choice with this method.
var RenderPage func(c *fiber.Ctx, url string, status int, args map[string]any) error = func(c *fiber.Ctx, url string, status int, args map[string]any) error {
	//todo: handle page rendering
	return nil
}
