# install
``` bash
go get -u github.com/donkw/gookie
```
# usage
``` go
chrome, err := gookie.NewChrome()
if err != nil {
  fmt.Printf("Error: %s\n", err)
  return
}
cookies, err := chrome.GetCookies(".huajiao.com")
if err != nil {
  fmt.Printf("Error: %s\n", err)
  return
}
fmt.Printf("Cookies: %v\n", cookies)
```