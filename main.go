package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	{ // bypass a package function call
		log.Println(rand.Int31()) // raises
		var randInt = rand.Int31
		log.Println(randInt()) // passes
	}

	{ // bypass by a type aliasing
		i := 0
		v := uintptr(unsafe.Pointer(&i)) // raises
		log.Println(v)

		type GoodPointer = unsafe.Pointer
		v = uintptr(GoodPointer(&i)) // passes
		log.Println(v)
	}

	{
		db, _ := sql.Open("sqlite3", ":memory:")
		q := fmt.Sprintf("SELECT * FROM foo where name = '%s'", os.Args[1])
		_, _ = db.Query(q) // raises

		// just by inlining we bypass (i.e. AST fix needed for rule G201 in gosec!)
		_, _ = db.Query(fmt.Sprintf("SELECT * FROM foo where name = '%s'", os.Args[1])) // passes
	}

	{ // https://github.com/securego/gosec/blob/master/rules/ssrf.go
		url := fmt.Sprintf("https://%s", os.Args[1])
		http.Get(url)                                   // raises
		http.Get(fmt.Sprintf("https://%s", os.Args[1])) // passes
	}

}

// G204 Audit use of command execution
// https://github.com/securego/gosec/blob/master/testutils/g204_samples.go
func runCmd(command string) {
	_ = syscall.Exec(command, []string{}, nil) // raises
	var Exec = syscall.Exec
	Exec(command, []string{}, nil) // passes
}

// bypass a package function call
func readFile(s string) {
	_, _ = os.ReadFile(s) // raises
	var read = os.ReadFile
	_, _ = read(s) // passes
}
