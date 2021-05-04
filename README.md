# Portier client test suite

This project contains a test suite for Portier client libraries. It is written
in Go, but can test libraries in any language.

```sh
go build -o client-tester
./client-tester -bin some-executable
```

Where `some-executable` is an executable that wraps the client library to test,
which we'll call 'integration'. The integration will be called with one
argument: the origin of a test broker that's running locally. It should
configure the client, then communicate over stdin/stdout with the test suite.
Stderr can be used for any additional logging (e.g. exceptions).

The stdin/stdout protocol is line-based (`\n` terminated lines), and each line
is a list of tab-separated strings. For requests sent by the test suite, the
first string is a command followed by arguments. For responses sent by the
integration, the first string is either `ok` followed by arguments, or `err`
followed by a single string error description.

Commands are:

- `echo <text>`: integration replies with `ok <text>`
- `auth <email>`: integration replies with `ok <auth URL>`
- `verify <id_token>`: integration replies with `ok <email>`

Here's an example flow, where we illustrate tabs with `||`, commands from the
test suite with `>>`, and responses from the integration with `<<`:

```
>> echo || test 1
<< ok || test 1
>> auth || John@example.com
<< ok || http://imaginary-server.test/fake-auth-route?client_id=...
>> verify || eyJraWQiOiJiYWQga2V5IiwiYWxnIjoiU...
<< ok || john@example.com
```
