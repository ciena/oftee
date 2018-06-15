# Packet Out to Switch Port
This example demonstrates how to send a packet out to a switch port using
`oftee`'s REST API.

## Help
```
This application is configured via the environment. The following environment
variables can be used:

KEY            TYPE             DEFAULT                  REQUIRED    DESCRIPTION
HELP           True or False    false                                show this message
OFTEE_API      String           http://127.0.0.1:8002                HOST:PORT on which to connect to OFTEE REST API
DEVICE         String                                    true        DPID of device on which to packet out
PORT           String                                    true        Port on device on which to packet out
PACKET_FILE    String                                    true        File from which to read packet to send, or '-' for stdin
```

## Usage
*assuming `GOPATH` is set, package are downloaded, and a switch exists with a
DPID of `0x0000663d64f9a142` and has a port `2`*
```bash
$ PACKET_FILE=src/github.com/ciena/oftee/misc/packet_out/eap.pkt \
          DEVICE=0x0000663d64f9a142 \
          PORT=2 \
          go run src/github.com/ciena/oftee/misc/packet_out/packet_out.go
```

## Port Constants
Along with port numbers the following strings can be used when specifying a
port:
- IN
- TABLE
- NORMAL
- FLOOD
- ALL
- CONTROLLER
- LOCAL
