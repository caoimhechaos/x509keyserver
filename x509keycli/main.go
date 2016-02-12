/*
 * (c) 2014-2016, Tonnerre Lombard <tonnerre@ancient-solutions.com>,
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
	"expvar"
	"flag"
	"github.com/tonnerre/x509keyserver"
	"log"
	"strconv"
	"strings"
	"time"
)

func main() {
	var kc *x509keyserver.X509KeyClient
	var fetch_interval, cache_prune_interval, timeout time.Duration
	var server, fetch_ids, id string
	var fetch_idlist []string
	var max_records int
	var err error

	flag.StringVar(&server, "server", "localhost:1234",
		"host:port pair of the x509 key server")
	flag.IntVar(&max_records, "max-cache-records", 4,
		"Maximum number of certificates to keep in the cache")
	flag.StringVar(&fetch_ids, "ids", "",
		"Comma-separated list of certificate IDs to fetch")
	flag.DurationVar(&fetch_interval, "fetch-interval", 0,
		"How long to wait between individual fetches (to test caching)")
	flag.DurationVar(&cache_prune_interval, "cache-prune-interval", time.Second,
		"How long to wait between two cache prunes (to test caching)")
	flag.DurationVar(&timeout, "timeout", 100*time.Millisecond,
		"How long to wait for server responses before cancelling them")
	flag.Parse()

	kc, err = x509keyserver.NewX509KeyClient(
		server, max_records, timeout, cache_prune_interval)
	if err != nil {
		log.Fatal("Unable to connect to ", server, ": ", err)
	}

	fetch_idlist = strings.Split(fetch_ids, ",")
	for _, id = range fetch_idlist {
		var index uint64
		var sz string
		index, err = strconv.ParseUint(id, 10, 64)
		if err != nil {
			log.Print("Unable to parse ", id, " as a number, skipping.")
			continue
		}
		sz = expvar.Get("x509-key-cache-size").String()
		_, err = kc.RetrieveCertificateByIndex(index)
		if err != nil {
			log.Print("Error retrieving certificate ", index, ": ", err)
		}
		log.Print("Cache size: ", sz, " -> ", expvar.Get("x509-key-cache-size").String())
		log.Print("Cache stats: hits: ", expvar.Get("x509-key-cache-hits").String(),
			", misses: ", expvar.Get("x509-key-cache-misses"))

		if fetch_interval > 0 {
			time.Sleep(fetch_interval)
		}
	}
}
