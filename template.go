package main

import (
	"html/template"
	"log"
)

const (
	PageLogin = `
<html>
  <head>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/pure/1.0.0/pure-min.css" />
  </head>
  <body>
    <section class="loginform">
      <form name="login" action="#" method="post" accept-charset="utf-8" class="pure-form">
        <input name="action" type="hidden" value="login"></li>
        <input type="text" name="username" placeholder="username" required>
        <input type="password" name="password" placeholder="password" required>
        <input type="submit" value="Login">
      </form>
    </section>
  </body>
</html>
`

	PageStatus = `
<html>
  <body>
    <form name="status" action="#" method="post">
      <input name="action" type="hidden" value="logout"></li>
      <input type="submit" value="Logout"></li>
    </form>
  </body>
</html>
`
)

var (
	TemplateLogin  *template.Template
	TemplateStatus *template.Template
)

func init() {
	var err error
	TemplateLogin, err = template.New("login").Parse(PageLogin)
	if err != nil {
		log.Fatal(err)
	}
	TemplateStatus, err = template.New("status").Parse(PageStatus)
	if err != nil {
		log.Fatal(err)
	}
}
