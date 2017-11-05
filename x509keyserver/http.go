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
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"github.com/caoimhechaos/x509keyserver"
	"github.com/caoimhechaos/x509keyserver/keydb"
)

// HTTP service to display known keys in a web site.
type HTTPKeyService struct {
	Db   *keydb.X509KeyDB
	Tmpl *template.Template
}

type httpExpandedKey struct {
	Pb      *x509keyserver.X509KeyData
	Expires time.Time
}

type templateData struct {
	Certs []*httpExpandedKey
	Next  uint64
	Error string
}

// Display a list of all known X.509 certificates.
func (ks *HTTPKeyService) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var keydata []*x509keyserver.X509KeyData
	var key *x509keyserver.X509KeyData
	var expanded []*httpExpandedKey
	var startidx, next uint64
	var startidxStr = req.FormValue("start")
	var display string = req.FormValue("display")
	var err error

	if display != "" {
		var cert *x509.Certificate
		startidx, err = strconv.ParseUint(display, 10, 64)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(err.Error()))
			return
		}
		cert, err = ks.Db.RetrieveCertificateByIndex(startidx)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(err.Error()))
			return
		}
		rw.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%d.der", startidx))
		rw.WriteHeader(http.StatusOK)
		rw.Write(cert.Raw)
		return
	}

	if startidxStr != "" {
		startidx, err = strconv.ParseUint(startidxStr, 10, 64)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			rw.Write([]byte(err.Error()))
			return
		}
	}

	keydata, err = ks.Db.ListCertificates(startidx, 20)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		rw.Write([]byte(err.Error()))
		return
	}

	for _, key = range keydata {
		var expkey *httpExpandedKey = new(httpExpandedKey)
		expkey.Pb = key
		expkey.Expires = time.Unix(int64(key.GetExpires()), 0)
		expanded = append(expanded, expkey)
		next = key.GetIndex() + 1
	}

	ks.Tmpl.Execute(rw, &templateData{
		Certs: expanded,
		Next:  next,
	})
}
