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

package keydb

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"database/cassandra"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/caoimhechaos/x509keyserver"
	"github.com/golang/protobuf/proto"
)

// X509KeyDB retrieves X.509 certificates from a Cassandra database.
type X509KeyDB struct {
	db *cassandra.RetryCassandraClient
}

// List of all column names in the certificate column family.
var certificate_DisplayColumns [][]byte = [][]byte{
	[]byte("subject"), []byte("issuer"), []byte("expires"),
}
var certificate_AllColumns [][]byte = [][]byte{
	[]byte("subject"), []byte("issuer"), []byte("expires"), []byte("der_certificate"),
}

// FormatCertSubject converts the specified certificate name field into a string
// which can be presented to the user.
func FormatCertSubject(name pkix.Name) []byte {
	var ret, val string

	for _, val = range name.Country {
		ret += fmt.Sprintf("/C=%s", val)
	}
	for _, val = range name.Province {
		ret += fmt.Sprintf("/SP=%s", val)
	}
	for _, val = range name.Locality {
		ret += fmt.Sprintf("/L=%s", val)
	}
	for _, val = range name.StreetAddress {
		ret += fmt.Sprintf("/A=%s", val)
	}
	for _, val = range name.Organization {
		ret += fmt.Sprintf("/O=%s", val)
	}
	for _, val = range name.OrganizationalUnit {
		ret += fmt.Sprintf("/OU=%s", val)
	}
	return []byte(fmt.Sprintf("%s/CN=%s", ret, name.CommonName))
}

// NewX509KeyDB connects to the X.509 key database given as "dbserver" and
// "keyspace".
func NewX509KeyDB(dbserver, keyspace string) (*X509KeyDB, error) {
	var client *cassandra.RetryCassandraClient
	var err error

	client, err = cassandra.NewRetryCassandraClient(dbserver)
	if err != nil {
		return nil, err
	}

	err = client.SetKeyspace(keyspace)
	if err != nil {
		return nil, err
	}

	return &X509KeyDB{
		db: client,
	}, nil
}

// ListCertificates lists the next "count" known certificates starting from
// "start_index".
func (db *X509KeyDB) ListCertificates(start_index uint64, count int32) ([]*x509keyserver.X509KeyData, error) {
	var ret []*x509keyserver.X509KeyData
	var cp *cassandra.ColumnParent = cassandra.NewColumnParent()
	var pred *cassandra.SlicePredicate = cassandra.NewSlicePredicate()
	var kr *cassandra.KeyRange = cassandra.NewKeyRange()
	var r []*cassandra.KeySlice
	var ks *cassandra.KeySlice
	var err error

	cp.ColumnFamily = "certificate"
	pred.ColumnNames = certificate_DisplayColumns

	if start_index > 0 {
		kr.StartKey = make([]byte, 8)
		binary.BigEndian.PutUint64(kr.StartKey, start_index)
	} else {
		kr.StartKey = make([]byte, 0)
	}
	kr.EndKey = make([]byte, 0)
	kr.Count = count

	r, err = db.db.GetRangeSlices(cp, pred, kr,
		cassandra.ConsistencyLevel_ONE)
	if err != nil {
		return ret, err
	}

	for _, ks = range r {
		var rv *x509keyserver.X509KeyData = new(x509keyserver.X509KeyData)
		var cos *cassandra.ColumnOrSuperColumn
		rv.Index = proto.Uint64(binary.BigEndian.Uint64(ks.Key))

		for _, cos = range ks.Columns {
			var col *cassandra.Column = cos.Column
			if col == nil {
				continue
			}

			if string(col.Name) == "subject" {
				rv.Subject = proto.String(string(col.Value))
			} else if string(col.Name) == "issuer" {
				rv.Issuer = proto.String(string(col.Value))
			} else if string(col.Name) == "issuer" {
				rv.Issuer = proto.String(string(col.Value))
			} else if string(col.Name) == "expires" {
				rv.Expires = proto.Uint64(binary.BigEndian.Uint64(col.Value))
			} else {
				return ret, errors.New("Unexpected column: " + string(col.Name))
			}
		}

		ret = append(ret, rv)
	}

	return ret, nil
}

// RetrieveCertificateByIndex retrieves the certificate with the given index
// number assigned by the issuer from the database.
func (db *X509KeyDB) RetrieveCertificateByIndex(index uint64) (*x509.Certificate, error) {
	var cp *cassandra.ColumnPath = cassandra.NewColumnPath()
	var r *cassandra.ColumnOrSuperColumn
	var key []byte = make([]byte, 8)
	var err error

	binary.BigEndian.PutUint64(key, index)

	cp.ColumnFamily = "certificate"
	cp.Column = []byte("der_certificate")

	r, err = db.db.Get(key, cp, cassandra.ConsistencyLevel_ONE)
	if err != nil {
		return nil, err
	}

	if r.Column == nil {
		return nil, errors.New("Column not found")
	}

	return x509.ParseCertificate(r.Column.Value)
}

// AddX509Certificate adds all relevant data for the given X.509 certificate.
func (db *X509KeyDB) AddX509Certificate(cert *x509.Certificate) error {
	var now time.Time = time.Now()
	var mmap = make(map[string]map[string][]*cassandra.Mutation)
	var mutation *cassandra.Mutation
	var expires uint64
	var key []byte = make([]byte, 8)
	var ts int64 = now.UnixNano() / 1000

	binary.BigEndian.PutUint64(key, cert.SerialNumber.Uint64())
	mmap[string(key)] = make(map[string][]*cassandra.Mutation)
	mmap[string(key)]["certificate"] = make([]*cassandra.Mutation, 0)

	mutation = cassandra.NewMutation()
	mutation.ColumnOrSupercolumn = cassandra.NewColumnOrSuperColumn()
	mutation.ColumnOrSupercolumn.Column = cassandra.NewColumn()
	mutation.ColumnOrSupercolumn.Column.Name = []byte("subject")
	mutation.ColumnOrSupercolumn.Column.Value = FormatCertSubject(cert.Subject)
	mutation.ColumnOrSupercolumn.Column.Timestamp = &ts
	mmap[string(key)]["certificate"] = append(
		mmap[string(key)]["certificate"], mutation)

	mutation = cassandra.NewMutation()
	mutation.ColumnOrSupercolumn = cassandra.NewColumnOrSuperColumn()
	mutation.ColumnOrSupercolumn.Column = cassandra.NewColumn()
	mutation.ColumnOrSupercolumn.Column.Name = []byte("issuer")
	mutation.ColumnOrSupercolumn.Column.Value = FormatCertSubject(cert.Issuer)
	mutation.ColumnOrSupercolumn.Column.Timestamp = &ts
	mmap[string(key)]["certificate"] = append(
		mmap[string(key)]["certificate"], mutation)

	expires = uint64(cert.NotAfter.Unix())

	mutation = cassandra.NewMutation()
	mutation.ColumnOrSupercolumn = cassandra.NewColumnOrSuperColumn()
	mutation.ColumnOrSupercolumn.Column = cassandra.NewColumn()
	mutation.ColumnOrSupercolumn.Column.Name = []byte("expires")
	mutation.ColumnOrSupercolumn.Column.Value = make([]byte, 8)
	binary.BigEndian.PutUint64(mutation.ColumnOrSupercolumn.Column.Value, expires)
	mutation.ColumnOrSupercolumn.Column.Timestamp = &ts
	mmap[string(key)]["certificate"] = append(
		mmap[string(key)]["certificate"], mutation)

	mutation = cassandra.NewMutation()
	mutation.ColumnOrSupercolumn = cassandra.NewColumnOrSuperColumn()
	mutation.ColumnOrSupercolumn.Column = cassandra.NewColumn()
	mutation.ColumnOrSupercolumn.Column.Name = []byte("der_certificate")
	mutation.ColumnOrSupercolumn.Column.Value = cert.Raw
	mutation.ColumnOrSupercolumn.Column.Timestamp = &ts
	mmap[string(key)]["certificate"] = append(
		mmap[string(key)]["certificate"], mutation)

	// Commit the data into the database.
	return db.db.BatchMutate(mmap, cassandra.ConsistencyLevel_QUORUM)
}
