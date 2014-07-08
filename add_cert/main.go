/*
 * (c) 2014, Caoimhe Chaos <caoimhechaos@protonmail.com>,
 *	     Starship Factory. All rights reserved.
 *
 * Redistribution and use in source  and binary forms, with or without
 * modification, are permitted  provided that the following conditions
 * are met:
 *
 * * Redistributions of  source code  must retain the  above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this  list of conditions and the  following disclaimer in
 *   the  documentation  and/or  other  materials  provided  with  the
 *   distribution.
 * * Neither  the name  of the Starship Factory  nor the  name  of its
 *   contributors may  be used to endorse or  promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS"  AND ANY EXPRESS  OR IMPLIED WARRANTIES  OF MERCHANTABILITY
 * AND FITNESS  FOR A PARTICULAR  PURPOSE ARE DISCLAIMED. IN  NO EVENT
 * SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL,  EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED  TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE,  DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT  LIABILITY,  OR  TORT  (INCLUDING NEGLIGENCE  OR  OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"

	"github.com/caoimhechaos/x509keyserver"
)

func main() {
	var pemblock *pem.Block
	var pemdata []byte
	var cert *x509.Certificate
	var kdb *x509keyserver.X509KeyDB
	var dbserver, keyspace string
	var certpath string
	var err error

	flag.StringVar(&certpath, "certificate-path", "cert.crt",
		"Name of the certificate file to read")

	flag.StringVar(&dbserver, "cassandra-server", "localhost:9160",
		"host:port pair of the Cassandra database server")
	flag.StringVar(&keyspace, "cassandra-keyspace", "x509certs",
		"Cassandra keyspace in which the relevant column families are stored")
	flag.Parse()

	// Set up the connection to the key database.
	kdb, err = x509keyserver.NewX509KeyDB(dbserver, keyspace)
	if err != nil {
		log.Fatal("Error connecting to key database: ", err)
	}

	pemdata, err = ioutil.ReadFile(certpath)
	if err != nil {
		log.Fatal("Unable to open ", certpath, ": ", err)
	}

	pemblock, _ = pem.Decode(pemdata)
	if pemblock != nil {
		pemdata = pemblock.Bytes
	}

	cert, err = x509.ParseCertificate(pemdata)
	if err != nil {
		log.Fatal("Error parsing certificate: ", err)
	}

	err = kdb.AddX509Certificate(cert)
	if err != nil {
		log.Fatal("Error storing decoded certificate in database: ", err)
	}
}
