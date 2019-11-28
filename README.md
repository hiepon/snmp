
[![Build Status](https://travis-ci.org/hiepon/snmp.svg?branch=master)](https://travis-ci.org/hiepon/snmp) [![Go Report Card](https://goreportcard.com/badge/github.com/hiepon/snmp)](https://goreportcard.com/report/github.com/hiepon/snmp) [![GoDoc](https://godoc.org/github.com/hiepon/snmp?status.svg)](https://godoc.org/github.com/hiepon/snmp)
# snmp
--
    import "github.com/hiepon/snmp"

Package snmp implements low-level support for SNMP with focus in SNMP agents.

At the encoding level it uses the hiepon/asn1 to parse and serialize
SNMP messages providing Go types for that.

The package also provides transport-independent support for creating custom SNMP
agents with small footprint.

A example of a simple SNMP UDP agent:

    package main

    import (
    	"log"
    	"net"
    	"time"

    	"github.com/hiepon/asn1"
    	"github.com/hiepon/snmp"
    )

    func main() {
    	agent := snmp.NewAgent()

    	// Set the read-only and read-write communities
    	agent.SetCommunities("publ", "priv")

    	// Register a read-only OID.
    	since := time.Now()
    	agent.AddRoManagedObject(
    		// sysUpTime
    		asn1.Oid{1, 3, 6, 1, 2, 1, 1, 3, 0},
    		func(oid asn1.Oid) (interface{}, error) {
    			seconds := int(time.Now().Sub(since) / time.Second)
    			return seconds, nil
    		})

    	// Register a read-write OID.
    	name := "example"
    	agent.AddRwManagedObject(
    		// sysName
    		asn1.Oid{1, 3, 6, 1, 2, 1, 1, 5, 0},
    		func(oid asn1.Oid) (interface{}, error) {
    			return name, nil
    		},
    		func(oid asn1.Oid, value interface{}) error {
    			strValue, ok := value.(string)
    			if !ok {
    				return snmp.VarErrorf(snmp.BadValue, "invalid type")
    			}
    			name = strValue
    			return nil
    		})

    	// Bind to an UDP port
    	addr, err := net.ResolveUDPAddr("udp", ":161")
    	if err != nil {
    		log.Fatal(err)
    	}
    	conn, err := net.ListenUDP("udp", addr)
    	if err != nil {
    		log.Fatal(err)
    	}

    	// Serve requests
    	for {
    		buffer := make([]byte, 1024)
    		n, source, err := conn.ReadFrom(buffer)
    		if err != nil {
    			log.Fatal(err)
    		}

    		buffer, err = agent.ProcessDatagram(buffer[:n])
    		if err != nil {
    			log.Println(err)
    			continue
    		}

    		_, err = conn.WriteTo(buffer, source)
    		if err != nil {
    			log.Fatal(err)
    		}
    	}
    }

## Usage

```go
const (
	NoError             = 0
	TooBig              = 1
	NoSuchName          = 2
	BadValue            = 3
	ReadOnly            = 4
	GenErr              = 5
	NoAccess            = 6
	WrongType           = 7
	WrongLength         = 8
	WrongEncoding       = 9
	WrongValue          = 10
	NoCreation          = 11
	InconsistentValue   = 12
	ResourceUnavailable = 13
	CommitFailed        = 14
	UndoFailed          = 15
	AuthorizationError  = 16
	NotWritable         = 17
	InconsistentName    = 18
)
```
SNMP error codes.

#### func  Asn1Context

```go
func Asn1Context() *asn1.Context
```
Asn1Context returns a new allocated asn1.Context and registers all the choice
types necessary for SNMPv1 and SNMPv2.

#### type Agent

```go
type Agent struct {
}
```

Agent is a transport independent engine to process SNMP requests.

#### func  NewAgent

```go
func NewAgent() *Agent
```
NewAgent create and initialize an agent.

#### func (*Agent) AddRoManagedObject

```go
func (a *Agent) AddRoManagedObject(oid asn1.Oid, getter Getter) error
```
AddRoManagedObject registers a read-only managed object.

#### func (*Agent) AddRwManagedObject

```go
func (a *Agent) AddRwManagedObject(oid asn1.Oid, getter Getter,
	setter Setter) error
```
AddRwManagedObject registers a read-write managed object.

The inteface{} values returned by a Getter or received by a Setter must be of
one of the following types:

    int
    string
    asn1.Null
    asn1.Oid
    snmp.Counter32
    snmp.Counter64
    snmp.IpAddress
    snmp.Opaque
    snmp.TimeTicks
    snmp.Unsigned32

#### func (*Agent) ProcessDatagram

```go
func (a *Agent) ProcessDatagram(requestBytes []byte) (responseBytes []byte, err error)
```
ProcessDatagram handles a binany SNMP message.

#### func (*Agent) ProcessMessage

```go
func (a *Agent) ProcessMessage(request *Message) (response *Message, err error)
```
ProcessMessage handles a SNMP Message.

#### func (*Agent) SetCommunities

```go
func (a *Agent) SetCommunities(public, private string)
```
SetCommunities defines the public and private communities.

#### func (*Agent) SetLogger

```go
func (a *Agent) SetLogger(logger *log.Logger)
```
SetLogger defines the logger used for internal messages.

#### type BulkPdu

```go
type BulkPdu struct {
	Identifier     int
	NonRepeaters   int
	MaxRepetitions int
	Variables      []Variable
}
```

BulkPdu is a generic type for other Protocol Data Units.

#### type Counter32

```go
type Counter32 uint32
```

Counter32 is a counter type.

#### type Counter64

```go
type Counter64 uint64
```

Counter64 is a counter type.

#### type EndOfMibView

```go
type EndOfMibView asn1.Null
```

EndOfMibView exception.

#### func (EndOfMibView) String

```go
func (e EndOfMibView) String() string
```

#### type GetBulkRequestPdu

```go
type GetBulkRequestPdu BulkPdu
```

GetBulkRequestPdu is used for bulk requests.

#### type GetNextRequestPdu

```go
type GetNextRequestPdu Pdu
```

GetNextRequestPdu works similarly to GetRequestPdu, but it's returned the value
for the next valid Oid.

#### type GetRequestPdu

```go
type GetRequestPdu Pdu
```

GetRequestPdu is used to request data.

#### type GetResponsePdu

```go
type GetResponsePdu Pdu
```

GetResponsePdu is used in responses to SNMP requests.

#### type Getter

```go
type Getter func(oid asn1.Oid) (interface{}, error)
```

Getter is a function called to return a managed object value.

#### type IPAddress

```go
type IPAddress [4]byte
```

IPAddress is a IPv4 address.

#### func (IPAddress) String

```go
func (ip IPAddress) String() string
```
String returns a representation of IPAddress in dot notation.

#### type InformRequestPdu

```go
type InformRequestPdu Pdu
```

InformRequestPdu is used for inform requests.

#### type Message

```go
type Message struct {
	Version   int
	Community string
	Pdu       interface{} `asn1:"choice:pdu"`
}
```

Message is the top level element of the SNMP protocol.

#### type NoSuchInstance

```go
type NoSuchInstance asn1.Null
```

NoSuchInstance exception.

#### func (NoSuchInstance) String

```go
func (e NoSuchInstance) String() string
```

#### type NoSuchObject

```go
type NoSuchObject asn1.Null
```

NoSuchObject exception.

#### func (NoSuchObject) String

```go
func (e NoSuchObject) String() string
```

#### type Opaque

```go
type Opaque []byte
```

Opaque is a type for blobs.

#### type Pdu

```go
type Pdu struct {
	Identifier  int
	ErrorStatus int
	ErrorIndex  int
	Variables   []Variable
}
```

Pdu is a generic type for other Protocol Data Units.

#### type SetRequestPdu

```go
type SetRequestPdu Pdu
```

SetRequestPdu is used to request data to be updated.

#### type Setter

```go
type Setter func(oid asn1.Oid, value interface{}) error
```

Setter is a function called to set a managed object value.

#### type TimeTicks

```go
type TimeTicks uint32
```

TimeTicks is a type for time.

#### type Unsigned32

```go
type Unsigned32 uint32
```

Unsigned32 is an integer type.

#### type V1TrapPdu

```go
type V1TrapPdu struct {
	Enterprise   asn1.Oid
	AgentAddr    IPAddress
	GenericTrap  int
	SpecificTrap int
	Timestamp    TimeTicks
	Variables    []Variable
}
```

V1TrapPdu is used when sending a trap in SNMPv1.

#### type V2TrapPdu

```go
type V2TrapPdu Pdu
```

V2TrapPdu is used when sending a trap in SNMPv2.

#### type VarError

```go
type VarError struct {
	Status  int
	Message string
}
```

VarError is an error type that can be returned by a Getter or a Setter. When
VarError is returned, it Status is used in the SNMP response.

#### func  VarErrorf

```go
func VarErrorf(status int, format string, values ...interface{}) VarError
```
VarErrorf creates a new Error with a formatted message.

#### func (VarError) Error

```go
func (e VarError) Error() string
```

#### type Variable

```go
type Variable struct {
	Name  asn1.Oid
	Value interface{} `asn1:"choice:val"`
}
```

Variable represents an entry of the variable bindings
