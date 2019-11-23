package snmp

import (
	"fmt"
	"testing"

	"github.com/hiepon/asn1"
)

// TODO test GetNextRequestPdu and SetRequestPdu

func getResquestForTest() []byte {
	// Version   = 1
	// Pdu       = GetRequest
	// Oid       = .iso.org.dod.internet.mgmt.mib-2.system.sysUpTime.sysUpTimeInstance.0
	// Community = "publ"
	data := []byte{
		0x30, 0x27, 0x02, 0x01, 0x00, 0x04, 0x04, 0x70, 0x75, 0x62, 0x6c, 0xa0,
		0x1c, 0x02, 0x04, 0x74, 0x25, 0x43, 0x6c, 0x02, 0x01, 0x00, 0x02, 0x01,
		0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01,
		0x01, 0x03, 0x00, 0x05, 0x00,
	}
	return data
}

func TestGet(t *testing.T) {

	uptimeOid := asn1.Oid{1, 3, 6, 1, 2, 1, 1, 3, 0}
	data := getResquestForTest()

	uptime := 123
	agent := NewAgent()
	agent.SetCommunities("publ", "priv")
	agent.AddRoManagedObject(uptimeOid,
		func(oid asn1.Oid) (interface{}, error) {
			return uptime, nil
		})
	data, err := agent.ProcessDatagram(data)
	if err != nil {
		t.Fatal(err)
	}

	message := Message{}
	_, err = Asn1Context().Decode(data, &message)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := message.Pdu.(GetResponsePdu)
	if !ok {
		t.Fatalf("Invalid PDU type: %T\n", message.Pdu)
	}
	if response.ErrorStatus != 0 {
		t.Fatalf("Response contains an error: %d\n", response.ErrorStatus)
	}
	if len(response.Variables) < 1 {
		t.Fatalf("Response is missing variables.\n")
	}
	if response.Variables[0].Value != uptime {
		t.Fatalf("Wrong response value %v\n", response.Variables[0].Value)
	}
}

func TestNoSuchName(t *testing.T) {

	uptimeOid := asn1.Oid{1, 3, 6, 1, 2, 1, 1, 3}
	data := getResquestForTest()

	agent := NewAgent()
	agent.SetCommunities("publ", "priv")
	agent.AddRoManagedObject(uptimeOid,
		func(oid asn1.Oid) (interface{}, error) {
			return 0, nil
		})
	data, err := agent.ProcessDatagram(data)
	if err != nil {
		t.Fatal(err)
	}

	message := Message{}
	_, err = Asn1Context().Decode(data, &message)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := message.Pdu.(GetResponsePdu)
	if !ok {
		t.Fatalf("Invalid PDU type: %T\n", message.Pdu)
	}
	if response.ErrorStatus != NoSuchName {
		t.Fatalf(
			"Response should contain error %d. Got %d instead.\n",
			NoSuchName, response.ErrorStatus)
	}
}

func TestError(t *testing.T) {

	uptimeOid := asn1.Oid{1, 3, 6, 1, 2, 1, 1, 3, 0}
	data := getResquestForTest()

	agent := NewAgent()
	agent.SetCommunities("publ", "priv")
	agent.AddRoManagedObject(uptimeOid,
		func(oid asn1.Oid) (interface{}, error) {
			return nil, VarErrorf(BadValue, "error")
		})
	data, err := agent.ProcessDatagram(data)
	if err != nil {
		t.Fatal(err)
	}

	message := Message{}
	_, err = Asn1Context().Decode(data, &message)
	if err != nil {
		t.Fatal(err)
	}
	response, ok := message.Pdu.(GetResponsePdu)
	if !ok {
		t.Fatalf("Invalid PDU type: %T\n", message.Pdu)
	}
	if response.ErrorStatus != BadValue {
		t.Fatalf(
			"Response should contain error %d. Got %d instead.\n",
			BadValue, response.ErrorStatus)
	}
}

func TestCommunity(t *testing.T) {

	uptimeOid := asn1.Oid{1, 3, 6, 1, 2, 1, 1, 3, 0}
	data := getResquestForTest()

	uptime := 123
	agent := NewAgent()
	agent.SetCommunities("secret", "secret")
	agent.AddRoManagedObject(uptimeOid,
		func(oid asn1.Oid) (interface{}, error) {
			return uptime, nil
		})
	data, err := agent.ProcessDatagram(data)
	if err == nil {
		t.Fatal("Request with wrong Community should fail.")
	}
}

func TestString(t *testing.T) {
	objs := []fmt.Stringer{
		IPAddress{192, 168, 0, 1},
		NoSuchObject{},
		NoSuchInstance{},
		EndOfMibView{},
	}
	for _, obj := range objs {
		if len(obj.String()) == 0 {
			t.Fatalf("Invalid string: %v\n", obj)
		}
	}

}
