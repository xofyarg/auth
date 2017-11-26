package main

import (
	"html/template"
	"log"
)

const (
	PageLogin = `
<html>
  <head>
    <style>
      input {
          font-size: 24pt;
      }
    </style>
  </head>
  <body>
      <form name="login" action="#" method="post" accept-charset="utf-8">
        <input name="action" type="hidden" value="login"></li>
        <input type="text" name="username" placeholder="username" required>
        <input type="password" name="password" placeholder="password" required>
        <input type="submit" value="Login">
      </form>
  </body>
</html>
`

	PageStatus = `
<html>
  <body>
    <form name="status" action="#" method="post">
      <input name="action" type="hidden" value="logout"></li>
      <table>
        {{$cur := .Current}}
        {{range $id, $session := .Sessions}}
          <tr>
            <td><button name="remove" value="{{$id}}">{{if eq $cur $id}}C{{else}}X{{end}}</button></td>
            <td>{{$session.UserAgent}}</td>
            <td>{{$session.CreateTime}}</td>
          </tr>
        {{end}}
      </table>
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
