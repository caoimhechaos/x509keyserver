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
	"flag"
	"html/template"
	"log"
	"net/http"
	"net/rpc"

	"github.com/caoimhechaos/x509keyserver"
)

func main() {
	var tmpl *template.Template
	var ks *x509keyserver.X509KeyServer
	var kdb *x509keyserver.X509KeyDB
	var bind string
	var tmpl_path, static_path string
	var dbserver, keyspace string
	var err error

	flag.StringVar(&bind, "bind", "[::]:8080",
		"host:port pair to bind the HTTP/RPC server to")
	flag.StringVar(&static_path, "static-path", ".",
		"Path to the required static files for the web interface")
	flag.StringVar(&tmpl_path, "template", "keylist.html",
		"Path to the template file for displaying")

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
	ks = &x509keyserver.X509KeyServer{
		Db: kdb,
	}

	// Register the RPC service.
	err = rpc.Register(ks)
	if err != nil {
		log.Fatal("Error registering RPC handler for the key server: ", err)
	}

	tmpl, err = template.ParseFiles(tmpl_path)
	if err != nil {
		log.Fatal("Error parsing template ", tmpl_path, ": ", err)
	}

	// Tell the HTTP server to handle RPCs.
	rpc.HandleHTTP()

	http.Handle("/", &x509keyserver.HTTPKeyService{
		Db:   kdb,
		Tmpl: tmpl,
	})
	http.Handle("/css/", http.FileServer(http.Dir(static_path)))
	http.Handle("/js/", http.FileServer(http.Dir(static_path)))

	err = http.ListenAndServe(bind, nil)
	if err != nil {
		log.Fatal("Error binding to ", bind, ": ", err)
	}
}
