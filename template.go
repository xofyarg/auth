package main

import (
	"html/template"
	"log"
)

const (
	PageLogin = `
<html>
  <section class="loginform">
  <form name="login" action="#" method="post" accept-charset="utf-8">
    <input name="action" type="hidden" value="login"></li>
    <input type="text" name="username" placeholder="username" required>
    <input type="password" name="password" placeholder="password" required>
    <input type="submit" value="Login">
  </form>
  </section>
</html>
`

	PageStatus = `
<html>
  <form name="status" action="#" method="post">
    <input name="action" type="hidden" value="logout"></li>
    <input type="submit" value="Logout"></li>
  </form>
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
