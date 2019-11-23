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
