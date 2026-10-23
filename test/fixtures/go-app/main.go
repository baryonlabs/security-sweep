// Fixture: golang.org/x/text/language is imported and called.
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() {
	tag, err := language.Parse("en-US")
	fmt.Println(tag, err)
}
