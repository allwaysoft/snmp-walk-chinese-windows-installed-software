// Copyright 2012 The GoSNMP Authors. All rights reserved.  Use of this
// source code is governed by a BSD-style license that can be found in the
// LICENSE file.

// This program demonstrates BulkWalk.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"golang.org/x/text/encoding/simplifiedchinese"
)

func snmpTimeString(c []byte) string {
	year := (int(c[0]) << 8) | int(c[1])
	return fmt.Sprintf("%d-%d-%d %02d:%02d:%02d.%d", year, c[2], c[3], c[4], c[5], c[6], c[7])
}

func main() {

	gosnmp.Default.Target = "127.0.0.1"
	gosnmp.Default.Community = "public"
	oid := ".1.3.6.1.2.1.25.6.3.1"
	gosnmp.Default.Timeout = time.Duration(10 * time.Second) // Timeout better suited to walking
	err := gosnmp.Default.Connect()
	if err != nil {
		fmt.Printf("Connect err: %v\n", err)
		os.Exit(1)
	}
	defer gosnmp.Default.Conn.Close()

	err = gosnmp.Default.BulkWalk(oid, printValue)
	if err != nil {
		fmt.Printf("Walk Error: %v\n", err)
		os.Exit(1)
	}
}

func printValue(pdu gosnmp.SnmpPDU) error {

	if strings.Contains(pdu.Name, ".1.3.6.1.2.1.25.6.3.1.2") {
		fmt.Printf("%s = ", pdu.Name)
		b := pdu.Value.([]byte)
		utf8Data2, _ := simplifiedchinese.GBK.NewDecoder().Bytes(b)
		fmt.Printf("STRING: %s\n", utf8Data2)
	}
	if strings.Contains(pdu.Name, ".1.3.6.1.2.1.25.6.3.1.4") {
		fmt.Printf("%s = ", pdu.Name)
		fmt.Printf("TYPE %d: %d\n", pdu.Type, gosnmp.ToBigInt(pdu.Value))
	}
	if strings.Contains(pdu.Name, ".1.3.6.1.2.1.25.6.3.1.5") {
		fmt.Printf("%s = ", pdu.Name)
		b := pdu.Value.([]byte)
		fmt.Printf("STRING: %s\n", snmpTimeString(b))
	}

	return nil
}
