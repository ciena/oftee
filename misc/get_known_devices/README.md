# Get Known Devices Tools
This example demonstrates how to query `oftee` for the DPIDs of the devices which
`oftee` is aware.

## Help
```
This application is configured via the environment. The following environment
variables can be used:

KEY          TYPE             DEFAULT                  REQUIRED    DESCRIPTION
HELP         True or False    false                                show this message
OFTEE_API    String           http://127.0.0.1:8002                HOST:PORT on which to connect to OFTEE REST API
```

## Usage
*assuming GOPATH is set, package are downloaded, and `jq` is installed for pretty printing `JSON`*
```bash
$ go run src/github.com/ciena/oftee/misc/get_known_devices/get_known_devices.go | jq .
{
  "devices": [
    "of:0x000062bfe0fd4e45",
    "of:0x0000663d64f9a142"
  ]
}
```
