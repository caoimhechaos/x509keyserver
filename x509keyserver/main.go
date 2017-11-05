/*
 * (c) 2014-2016, Caoimhe Chaos <caoimhechaos@protonmail.com>,
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
	"net"
	"net/http"

	"github.com/caoimhechaos/x509keyserver"
	"github.com/caoimhechaos/x509keyserver/keydb"
	"google.golang.org/grpc"
)

func main() {
	var tmpl *template.Template
	var ks *X509KeyServer
	var kdb *keydb.X509KeyDB
	var httpBind, bind string
	var tmplPath, staticPath string
	var dbserver, keyspace string
	var server *grpc.Server
	var l net.Listener
	var err error

	flag.StringVar(&bind, "bind", "[::]:1234",
		"host:port pair to bind the RPC server to")
	flag.StringVar(&httpBind, "bind-http", "",
		"host:port pair to bind the HTTP server to")
	flag.StringVar(&staticPath, "static-path", ".",
		"Path to the required static files for the web interface")
	flag.StringVar(&tmplPath, "template", "keylist.html",
		"Path to the template file for displaying")

	flag.StringVar(&dbserver, "cassandra-server", "localhost:9160",
		"host:port pair of the Cassandra database server")
	flag.StringVar(&keyspace, "cassandra-keyspace", "x509certs",
		"Cassandra keyspace in which the relevant column families are stored")
	flag.Parse()

	// Set up the connection to the key database.
	kdb, err = keydb.NewX509KeyDB(dbserver, keyspace)
	if err != nil {
		log.Fatal("Error connecting to key database: ", err)
	}
	ks = &X509KeyServer{
		Db: kdb,
	}

	// Register the RPC service.
	l, err = net.Listen("tcp", bind)
	if err != nil {
		log.Fatal("Error listening on ", bind, ": ", err)
	}

	server = grpc.NewServer()
	x509keyserver.RegisterX509KeyServerServer(server, ks)

	// Prepare the HTTP server
	if len(httpBind) > 0 {
		tmpl, err = template.ParseFiles(tmplPath)
		if err != nil {
			log.Fatal("Error parsing template ", tmplPath, ": ", err)
		}

		http.Handle("/", &HTTPKeyService{
			Db:   kdb,
			Tmpl: tmpl,
		})
		http.Handle("/css/", http.FileServer(http.Dir(staticPath)))
		http.Handle("/js/", http.FileServer(http.Dir(staticPath)))

		go server.Serve(l)
		err = http.ListenAndServe(httpBind, nil)
		if err != nil {
			log.Fatal("Error binding to ", httpBind, ": ", err)
		}
	} else {
		err = server.Serve(l)
		if err != nil {
			log.Fatal("Error serving RPCs on ", bind, ": ", err)
		}
	}
}
