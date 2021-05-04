package main

import (
	"fmt"
	"log"
	"net/url"
)

var numTests int // for numbering output

// allOk can be set to false for a non-zero exit status.
// The assert functions do this for you.
var allOk = true

// test wraps test functions with logging.
func test(descr string, block func()) {
	numTests++
	log.Printf("Test %d: %s", numTests, descr)

	// sync up
	sync := fmt.Sprintf("test %d", numTests)
	proc.writeLine("echo", sync)
	cmd := proc.readLine()
	if cmd[0] != "ok" || cmd[1] != sync {
		log.Fatal("Test runner out of sync")
	}

	block()
}

// assert logs the result of a check.
func assert(val bool, descr string) bool {
	if !val {
		allOk = false
		log.Printf("  ERR  %s", descr)
		return false
	}
	log.Printf("  OK   %s", descr)
	return true
}

// assertEq logs values if they are unequal.
func assertEq(a, b interface{}, descr string) bool {
	if !assert(a == b, descr) {
		log.Printf("got: %+v", a)
		log.Printf("want: %+v", b)
		return false
	}
	return true
}

// assertOK logs the error if not nil.
func assertOK(err error, descr string) bool {
	if !assert(err == nil, descr) {
		log.Printf("%s", err.Error())
		return false
	}
	return true
}

// quickStart sends the authentication request and returns a nonce.
// Useful for tests focussing on the verification step.
func quickStart(email string) string {
	var nonce string
	proc.writeLine("auth", email)
	cmd := proc.readLine()
	if cmd[0] == "ok" {
		authURL, err := url.Parse(cmd[1])
		if err == nil {
			nonce = authURL.Query().Get("nonce")
		}
	}
	assert(nonce != "", "start authentication request")
	return nonce
}
