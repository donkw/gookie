package gookie

import (
	"fmt"
	"testing"
)

func TestGetCookies(t *testing.T) {
	ch, err := NewChrome()
	if err != nil {
		t.Fatal(err)
	}
	cookies, err := ch.GetCookies(".baidu.com")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	fmt.Printf("Cookies: %v\n", cookies)
}
