// -*- coding: utf-8 -*-

package snmp

import (
	"bytes"
	"testing"

	"github.com/hiepon/asn1"
)

func TestEncDecIPAddress(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: IPAddress([4]byte{1, 2, 3, 4}),
	}

	b := []byte{
		0x30, 0x06, 0x40, 0x04,
		0x01, 0x02, 0x03, 0x04,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if result.Value.(IPAddress) != msg.Value.(IPAddress) {
		t.Errorf("Decode error. %d", result)
	}
}

func TestEncDecCounter32(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: Counter32(0x1234),
	}

	b := []byte{
		0x30, 0x04, 0x41, 0x02,
		0x12, 0x34,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if result.Value.(Counter32) != msg.Value.(Counter32) {
		t.Errorf("Decode error. %d", result)
	}
}

func TestEncDecUnsigned32(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: Unsigned32(0x1234),
	}

	b := []byte{
		0x30, 0x04, 0x42, 0x02,
		0x12, 0x34,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if result.Value.(Unsigned32) != result.Value.(Unsigned32) {
		t.Errorf("Decode error. %v", result.Value)
	}
}

func TestEncDecTimeTicks(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: TimeTicks(0x1234),
	}

	b := []byte{
		0x30, 0x04, 0x43, 0x02,
		0x12, 0x34,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if result.Value.(TimeTicks) != result.Value.(TimeTicks) {
		t.Errorf("Decode error. %v", result.Value)
	}
}

func TestEncDecOpaque(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: Opaque([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
	}

	b := []byte{
		0x30, 0x0a, 0x44, 0x08,
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if bytes.Compare(result.Value.(Opaque), msg.Value.(Opaque)) != 0 {
		t.Errorf("Decode error. %d", result.Value)
	}
}

func TestEncDecNull(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: asn1.Null{},
	}

	b := []byte{
		0x30, 0x02, 0x05, 0x00,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if _, ok := result.Value.(asn1.Null); !ok {
		t.Errorf("Decode error. %d", result.Value)
	}
}

func TestEncDecInteger(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: int(1234),
	}

	b := []byte{
		0x30, 0x04, 0x02, 0x02,
		0x04, 0xd2,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if result.Value.(int) != msg.Value.(int) {
		t.Errorf("Decode error. %v %v", result.Value, msg.Value)
	}
}

func TestEncDecOctetString(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: "Hello",
	}

	b := []byte{
		0x30, 0x07, 0x04, 0x05,
		0x48, 0x65, 0x6c, 0x6c,
		0x6f,
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}
	if result.Value.(string) != msg.Value.(string) {
		t.Errorf("Decode error. %v %v", result.Value, msg.Value)
	}
}

func TestEncDecObjectIdentifier(t *testing.T) {
	var (
		data []byte
		err  error
	)

	type Message struct {
		Value interface{} `asn1:"choice:val"`
	}
	msg := Message{
		Value: asn1.Oid{1, 3},
	}

	b := []byte{
		// 48 3 6 1 0
		0x30, 0x03, 0x06, 0x01,
		0x2b, // 1*40+3
	}

	ctxt := Asn1Context()
	ctxt.SetDer(true, true)

	data, err = ctxt.Encode(msg)
	if err != nil {
		t.Fatalf("Encode error. %s", err)
	}
	if bytes.Compare(data, b) != 0 {
		t.Fatalf("Encode error. %v", data)
	}

	var result Message
	if _, err = ctxt.Decode(data, &result); err != nil {
		t.Errorf("Decode error. %s", err)
	}

	if result.Value.(asn1.Oid).Cmp(msg.Value.(asn1.Oid)) != 0 {
		t.Errorf("Decode error. '%#v' '%#v'", result.Value, msg.Value)
	}
}
