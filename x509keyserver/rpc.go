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
	"crypto/x509"

	"github.com/caoimhechaos/x509keyserver"
	"github.com/caoimhechaos/x509keyserver/keydb"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
)

// X509KeyServer implements the X.509 key server RPC interface.
type X509KeyServer struct {
	Db *keydb.X509KeyDB
}

// ListCertificates lists the next number of known certificates starting from
// the specified start index.
func (s *X509KeyServer) ListCertificates(
	c context.Context, req *x509keyserver.X509KeyDataListRequest) (
	res *x509keyserver.X509KeyDataList, err error) {
	res = new(x509keyserver.X509KeyDataList)
	res.Records, err = s.Db.ListCertificates(req.GetStartIndex(), req.GetCount())
	return
}

// RetrieveCertificateByIndex retrieves the certificate with the given index
// number assigned by the issuer from the database.
func (s *X509KeyServer) RetrieveCertificateByIndex(
	c context.Context, req *x509keyserver.X509KeyDataRequest) (
	ret *x509keyserver.X509KeyData, err error) {
	var cert *x509.Certificate

	ret = new(x509keyserver.X509KeyData)
	cert, err = s.Db.RetrieveCertificateByIndex(req.GetIndex())
	if err != nil {
		return
	}

	ret.DerCertificate = cert.Raw
	ret.Expires = proto.Uint64(uint64(cert.NotAfter.Unix()))
	ret.Index = proto.Uint64(req.GetIndex())
	ret.Issuer = proto.String(string(keydb.FormatCertSubject(cert.Issuer)))
	ret.Subject = proto.String(string(keydb.FormatCertSubject(cert.Subject)))

	return
}
