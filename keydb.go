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

package x509keyserver

import (
	"crypto/x509"
	"database/cassandra"
	"encoding/binary"
	"errors"

	"code.google.com/p/goprotobuf/proto"
)

// Object for retrieving X.509 certificates from the Cassandra database.
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

// Connect to the X.509 key database given as "dbserver" and "keyspace".
func NewX509KeyDB(dbserver, keyspace string) (*X509KeyDB, error) {
	var client *cassandra.RetryCassandraClient
	var ire *cassandra.InvalidRequestException
	var err error

	client, err = cassandra.NewRetryCassandraClient(dbserver)
	if err != nil {
		return nil, err
	}

	ire, err = client.SetKeyspace(keyspace)
	if ire != nil {
		return nil, errors.New(ire.Why)
	}
	if err != nil {
		return nil, err
	}

	return &X509KeyDB{
		db: client,
	}, nil
}

// List the next "count" known certificates starting from "start_index".
func (db *X509KeyDB) ListCertificates(start_index uint64, count int32) ([]*X509KeyData, error) {
	var ret []*X509KeyData
	var cp *cassandra.ColumnParent = cassandra.NewColumnParent()
	var pred *cassandra.SlicePredicate = cassandra.NewSlicePredicate()
	var kr *cassandra.KeyRange = cassandra.NewKeyRange()
	var r []*cassandra.KeySlice
	var ks *cassandra.KeySlice
	var ire *cassandra.InvalidRequestException
	var ue *cassandra.UnavailableException
	var te *cassandra.TimedOutException
	var err error

	cp.ColumnFamily = "certificate"
	pred.ColumnNames = certificate_DisplayColumns

	if start_index > 0 {
		binary.BigEndian.PutUint64(kr.StartKey, start_index)
	} else {
		kr.StartKey = make([]byte, 0)
	}
	kr.EndKey = make([]byte, 0)
	kr.Count = count

	r, ire, ue, te, err = db.db.GetRangeSlices(cp, pred, kr,
		cassandra.ConsistencyLevel_ONE)
	if ire != nil {
		return ret, errors.New(ire.Why)
	}
	if ue != nil {
		return ret, errors.New("Unavailable")
	}
	if te != nil {
		return ret, errors.New("Timed out")
	}
	if err != nil {
		return ret, err
	}

	for _, ks = range r {
		var rv *X509KeyData = new(X509KeyData)
		var cos *cassandra.ColumnOrSuperColumn
		rv.Index = proto.Uint64(binary.BigEndian.Uint64(ks.Key))

		for _, cos = range ks.Columns {
			var col *cassandra.Column = cos.Column
			if col != nil {
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

// Retrieve the certificate with the given index number from the database.
func (db *X509KeyDB) RetrieveCertificateByIndex(index uint64) (*x509.Certificate, error) {
	var cp *cassandra.ColumnPath = cassandra.NewColumnPath()
	var r *cassandra.ColumnOrSuperColumn
	var ire *cassandra.InvalidRequestException
	var nfe *cassandra.NotFoundException
	var ue *cassandra.UnavailableException
	var te *cassandra.TimedOutException
	var key []byte
	var err error

	binary.BigEndian.PutUint64(key, index)

	cp.ColumnFamily = "certificate"
	cp.Column = []byte("der_certificate")

	r, ire, nfe, ue, te, err = db.db.Get(key, cp, cassandra.ConsistencyLevel_ONE)
	if ire != nil {
		return nil, errors.New(ire.Why)
	}
	if nfe != nil {
		return nil, errors.New("Certificate not found")
	}
	if ue != nil {
		return nil, errors.New("Unavailable")
	}
	if te != nil {
		return nil, errors.New("Timed out")
	}
	if err != nil {
		return nil, err
	}

	if r.Column == nil {
		return nil, errors.New("Column not found")
	}

	return x509.ParseCertificate(r.Column.Value)
}
