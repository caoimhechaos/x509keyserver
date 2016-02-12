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

package x509keyserver

import (
	"crypto/x509"
	"expvar"
	"sync"
	"time"

	"github.com/caoimhechaos/go-urlconnection"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// Implementation of the X.509 key server RPC interface from the client side.
// Essentially implements a caching client which will keep up to
// "max_cache_size" records in its cache. They never expire since certificate
// index numbers shouldn't be reused and should therefor be unique.
type X509KeyClient struct {
	client               X509KeyServerClient
	key_cache            map[uint64]*cacheRecord
	cache_lock           sync.RWMutex
	max_cache_size       int
	timeout              time.Duration
	cache_prune_interval time.Duration
}

type cacheRecord struct {
	Cert     *x509.Certificate
	LastUsed time.Time
}

var key_cache_size = expvar.NewInt("x509-key-cache-size")
var key_cache_requests = expvar.NewInt("x509-key-cache-requests")
var key_cache_hits = expvar.NewInt("x509-key-cache-hits")
var key_cache_misses = expvar.NewInt("x509-key-cache-misses")
var key_cache_errors = expvar.NewMap("x509-key-cache-errors")

// Create a new caching X509 key client. "server" will be the server to
// connect to for retrieving certificates, "max_size" is the maximum size
// we'll want the cache to have, and "cache_prune_interval" is the
// maximum amount of time we'll allow the cache to go over quota.
func NewX509KeyClient(
	server string,
	max_size int,
	timeout time.Duration,
	cache_prune_interval time.Duration) (*X509KeyClient, error) {
	var conn *grpc.ClientConn
	var ret *X509KeyClient
	var err error

	conn, err = grpc.Dial(server,
		grpc.WithDialer(urlconnection.ConnectTimeout),
		grpc.WithTimeout(timeout))
	if err != nil {
		return nil, err
	}

	ret = &X509KeyClient{
		client:               NewX509KeyServerClient(conn),
		key_cache:            make(map[uint64]*cacheRecord),
		max_cache_size:       max_size,
		timeout:              timeout,
		cache_prune_interval: cache_prune_interval,
	}

	// Spawn a thread to regularly trim the cache back to its maximum size.
	go ret.TrimCache()
	return ret, nil
}

// Clean up old certificate entries.
func (cl *X509KeyClient) TrimCache() {
	c := time.Tick(cl.cache_prune_interval)

	// Negative cache sizes don't make any sense.
	if cl.max_cache_size < 0 {
		return
	}

	for _ = range c {
		cl.cache_lock.Lock()
		for len(cl.key_cache) > cl.max_cache_size {
			var cur, min *cacheRecord
			var key, min_key uint64
			for key, cur = range cl.key_cache {
				if min == nil || cur.LastUsed.Before(min.LastUsed) {
					min_key = key
					min = cur
				}
			}

			// We found a minimal key, delete it.
			if min != nil {
				delete(cl.key_cache, min_key)
				key_cache_size.Set(int64(len(cl.key_cache)))
			}
		}
		cl.cache_lock.Unlock()
	}
}

// Retrieve the certificate associated with the given key ID.
func (cl *X509KeyClient) RetrieveCertificateByIndex(index uint64) (*x509.Certificate, error) {
	var res *X509KeyData
	var c context.Context
	var cert *x509.Certificate
	var cr *cacheRecord
	var err error
	var ok bool

	c, _ = context.WithTimeout(context.Background(), cl.timeout)

	key_cache_requests.Add(1)

	cl.cache_lock.RLock()
	if cr, ok = cl.key_cache[index]; ok {
		key_cache_hits.Add(1)
		cr.LastUsed = time.Now()
		defer cl.cache_lock.RUnlock()
		return cr.Cert, nil
	}
	cl.cache_lock.RUnlock()

	key_cache_misses.Add(1)
	res, err = cl.client.RetrieveCertificateByIndex(
		c, &X509KeyDataRequest{Index: proto.Uint64(index)})
	if err != nil {
		key_cache_errors.Add(err.Error(), 1)
		return nil, err
	}

	cert, err = x509.ParseCertificate(res.GetDerCertificate())
	if err != nil {
		key_cache_errors.Add(err.Error(), 1)
		return nil, err
	}

	cr = new(cacheRecord)
	cr.Cert = cert
	cr.LastUsed = time.Now()

	cl.cache_lock.Lock()
	cl.key_cache[index] = cr
	key_cache_size.Set(int64(len(cl.key_cache)))
	cl.cache_lock.Unlock()

	return cert, nil
}
