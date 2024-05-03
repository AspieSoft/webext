# WebExt

A collection of website middleware to extend basic tasks for gofiber.

Note: this module assumes you are using [gofiber/v2](https://github.com/gofiber/fiber)

## Installation

```shell script
go get github.com/AspieSoft/webext

# dependencies
go get github.com/gofiber/fiber/v2
```

## Usage

```go

package main

import (
  "github.com/AspieSoft/webext"
  "github.com/gofiber/fiber/v2"
)

func main(){
  app := fiber.New()

  origins := []string{
    "localhost",
    "example.com",
  }

  proxies := []string{
    "127.0.0.1",
    "192.168.0.1",
  }

  // enforce specific domain and ip origins
  app.Use(webext.VerifyOrigin(origins, proxies, func(c *fiber.Ctx, err error) error {
    c.SendStatus(403)
    return c.SendString(err.Error())
  }))

  // auto redirect http to https
  app.Use(webext.RedirectSSL(8080, 8443))

  // do anything with gofiber
  app.Get("/", func(c *fiber.Ctx) error {
    return c.SendString("Hello, World!")
  })

  // listen to both http and https ports and
  // auto generate a self signed ssl certificate
  // (will also auto renew every year)
  webext.ListenAutoTLS(app, 8080, 8443, "db/ssl/auto_ssl", proxies)

  // by using self signed certs, you can use a proxy like cloudflare and
  // not have to worry about verifying a certificate athority like lets encrypt
}

```
