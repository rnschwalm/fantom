//
// Copyright (c) 2026, Brian Frank and Andy Frank
// Licensed under the Academic Free License version 3.0
//
// History:
//   15 Apr 2026 Ross Schwalm   Creation
//

using crypto
using asn1
using inet

**
** Test cases for Certificate Signing Request (CSR) functionality
**
class JCsrTest : CryptoTest
{

  Void testCsrWithDnsSan()
  {
    pair := crypto.genKeyPair("RSA", 2048)
    subjectDn := "cn=example.com,o=Example Corp"

    sans := ["example.com", "www.example.com", "api.example.com", San.dns("fantom.org")]
    csr := crypto.genCsr(pair, subjectDn, ["subjectAltNames": sans])

    verifyEq(csr.subject, "O=Example Corp,CN=example.com")
    verifyNotNull(csr.opts)

    pem := csr.toStr
    verify(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"))

    decodedCsr := crypto.loadPem(pem.in) as Csr
    verifyNotNull(decodedCsr)

    verifyTrue(csr.subjectAltNames.size == 4)
    verifyEq(((San)csr.subjectAltNames[0]).type, SanType.dNSName)
    verifyEq(((San)csr.subjectAltNames[0]).val, "example.com")
    verifyEq(((San)csr.subjectAltNames[1]).type, SanType.dNSName)
    verifyEq(((San)csr.subjectAltNames[1]).val, "www.example.com")
    verifyEq(((San)csr.subjectAltNames[2]).type, SanType.dNSName)
    verifyEq(((San)csr.subjectAltNames[2]).val, "api.example.com")
    verifyEq(((San)csr.subjectAltNames[3]).type, SanType.dNSName)
    verifyEq(((San)csr.subjectAltNames[3]).val, "fantom.org")
  }

  Void testCsrWithIpSan()
  {
    pair := crypto.genKeyPair("RSA", 2048)
    subjectDn := "CN=Fantom"

    sans := Obj[IpAddr("192.168.1.100"), IpAddr("10.0.0.50"), San.ip("10.0.0.1")]
    csr := crypto.genCsr(pair, subjectDn, ["subjectAltNames": sans])

    verifyEq(csr.subject, subjectDn)

    pem := csr.toStr
    verify(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"))

    decodedCsr := crypto.loadPem(pem.in) as Csr
    verifyNotNull(decodedCsr)

    verifyTrue(csr.subjectAltNames.size == 3)
    verifyEq(((San)csr.subjectAltNames[0]).type, SanType.iPAddress)
    verifyEq(((San)csr.subjectAltNames[0]).val, IpAddr("192.168.1.100"))
    verifyEq(((San)csr.subjectAltNames[1]).type, SanType.iPAddress)
    verifyEq(((San)csr.subjectAltNames[1]).val, IpAddr("10.0.0.50"))
    verifyEq(((San)csr.subjectAltNames[2]).type, SanType.iPAddress)
    verifyEq(((San)csr.subjectAltNames[2]).val, IpAddr("10.0.0.1"))
  }

  Void testCsrWithUriSan()
  {
    pair := crypto.genKeyPair("RSA", 2048)
    subjectDn := "CN=Fantom"

    sans := Obj[
      `https://api.example.com`,
      `https://api-v2.example.com`,
      San.uri("https://internal.example.com")
    ]

    csr := crypto.genCsr(pair, subjectDn, ["subjectAltNames": sans])

    verifyEq(csr.subject, subjectDn)
    verifyNotNull(csr.toStr)
    verifyTrue(csr.subjectAltNames.size == 3)
    verifyEq(((San)csr.subjectAltNames[0]).type, SanType.uniformResourceIdentifier)
    verifyEq(((San)csr.subjectAltNames[0]).val, "https://api.example.com/")
    verifyEq(((San)csr.subjectAltNames[1]).type, SanType.uniformResourceIdentifier)
    verifyEq(((San)csr.subjectAltNames[1]).val, "https://api-v2.example.com/")
    verifyEq(((San)csr.subjectAltNames[2]).type, SanType.uniformResourceIdentifier)
    verifyEq(((San)csr.subjectAltNames[2]).val, "https://internal.example.com")

    pem := csr.toStr
    verify(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"))

    decodedCsr := crypto.loadPem(pem.in) as Csr
    verifyNotNull(decodedCsr)
  }

  Void testCsrWithRFC822San()
  {
    pair := crypto.genKeyPair("RSA", 2048)
    subjectDn := "CN=Fantom"

    sans := Obj[San.email("user@fantom.org")]
    csr := crypto.genCsr(pair, subjectDn, ["subjectAltNames": sans])

    verifyEq(csr.subject, subjectDn)

    pem := csr.toStr
    verify(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"))

    decodedCsr := crypto.loadPem(pem.in) as Csr
    verifyNotNull(decodedCsr)

    decodedSans := decodedCsr.subjectAltNames
    verifyEq(decodedSans.size, 1)
    verifyEq(((San)decodedSans[0]).type, SanType.rfc822Name)
    verifyEq(((San)decodedSans[0]).val, "user@fantom.org")
  }

  Void testCsrWithRegisteredIdSan()
  {
    pair := crypto.genKeyPair("RSA", 2048)
    subjectDn := "CN=Fantom"

    sans := Obj[San.registeredID("1.2.3.4.5.6")]
    csr := crypto.genCsr(pair, subjectDn, ["subjectAltNames": sans])

    verifyEq(csr.subject, subjectDn)

    pem := csr.toStr
    verify(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"))

    decodedCsr := crypto.loadPem(pem.in) as Csr
    verifyNotNull(decodedCsr)

    decodedSans := decodedCsr.subjectAltNames
    verifyEq(decodedSans.size, 1)
    verifyEq(((San)decodedSans[0]).type, SanType.registeredID)
    verifyEq(((San)decodedSans[0]).val, "1.2.3.4.5.6")
  }

  Void testCsrWithMixedSans()
  {
    pair := crypto.genKeyPair("RSA", 2048)
    subjectDn := "CN=Fantom"

    sans := Obj[
      "test.example.com",
      "www.test.example.com",
      `https://test.example.com`,
      IpAddr("192.168.1.1"),
      IpAddr("10.0.0.1")
    ]

    csr := crypto.genCsr(pair, subjectDn, ["subjectAltNames": sans])

    verifyEq(csr.subject, subjectDn)

    verifyEq(csr.subject, subjectDn)

    pem := csr.toStr
    decodedCsr := crypto.loadPem(pem.in) as Csr
    verifyNotNull(decodedCsr)
    verifyEq(decodedCsr.subject, "CN=Fantom")
    Obj[] values := decodedCsr.subjectAltNames.mapNotNull |san| { san.val }
    verifyEq(values, Obj[
                      "test.example.com",
                      "www.test.example.com",
                      "https://test.example.com/",
                      IpAddr("192.168.1.1"),
                      IpAddr("10.0.0.1")])
  }

  Void testOpensslCsr()
  {
    openssl := Str<|-----BEGIN CERTIFICATE REQUEST-----
                    MIIC1jCCAb4CAQAwUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlZBMREwDwYDVQQH
                    DAhSaWNobW9uZDEPMA0GA1UECgwGRmFudG9tMRMwEQYDVQQDDApmYW50b20ub3Jn
                    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuj4CHcCSOWo0T7l3L6E+
                    +fld2i6jkGfFNlajDlGR10rHuOrkTxaMbz9JTxrQIPQEYz8ewDskXPsqD5j17nNs
                    xrG/pMGB6gspBJeVFWIvKyxHfzKvZ8YN4h1BM/8shRwrENhB5LxEerai68/l78az
                    IsBq+w8AUV3H8MSo3tqhGR9eihlkb66XEXbmpJ3p8sB2Mskr5z4IUAqiWPLy30/H
                    6+yZfQuWAQci7KT1m8/DHpDo0vu6y7SZlNwW15WOZtoZBZiNpkahjSlk2s3OCrk4
                    5ql6zDH6zdSvQ2unS4VinEaCGRkkVVFS0qTQd/3tkEHgLggkiNKDyAV9cqE5QGP9
                    owIDAQABoD4wPAYJKoZIhvcNAQkOMS8wLTArBgNVHREEJDAiggpmYW50b20ub3Jn
                    gg53d3cuZmFudG9tLm9yZ4cEwKgBATANBgkqhkiG9w0BAQsFAAOCAQEAkDBjSBaj
                    Pc8MvJjXGPLwWChWGBcXYxIlAtKYtE/oZ+qmssFaBKHzMb5p6nO+LpL7OtPy7/Qu
                    /XqhIVa+PGkCaifNOG7WH7V80Y6wD5Ek87uFcsra1J40fX76+Mqh85oLBtMefxsC
                    76W8N+5svOI8xWLzyDs6Wpnm6iIWhSVHz/XYo/hxB1s/Z8rvXwFBquiiBwoYHM5j
                    nyC8767OMG6RQ5QBHhiZ5RUEDe2DxRlf19cjYyW+UNLoGaINdTP5YLylSO2ZHxG2
                    6M93q+wCZ8qJk5TgPEYWXp2HJfqTfMJVGwCKqlZ3OHmAwTMLAkVGyT2C0YBm55XX
                    sAH0mg+4tWQndw==
                    -----END CERTIFICATE REQUEST-----|>

    decodedCsr := crypto.loadPem(openssl.in) as Csr
    verifyNotNull(decodedCsr)
    verifyEq(decodedCsr.subject, "C=US,ST=VA,L=Richmond,O=Fantom,CN=fantom.org")

    sans := decodedCsr.subjectAltNames
    verifyEq(sans.size, 3)

    Obj[] values := sans.mapNotNull |san| { san.val }
    verifyEq(values, Obj["fantom.org", "www.fantom.org", IpAddr("192.168.1.1")])
  }

  Void testCsrSanToSignedCert()
  {
    pair := crypto.genKeyPair("RSA", 2048)
    subjectDn := "CN=Fantom"

    sans := ["san-test.fantom.org",
             "www.san-test.fantom.org",
             IpAddr("192.168.1.1"),
             San.ip("192.168.1.2"),
             San.email("user@fantom.org"),
             `https://fantom.org/doc`,
             San.uri("https://fantom.org")]
    csr := crypto.genCsr(pair, subjectDn, ["subjectAltNames": sans])

    cert := crypto.certSigner(csr)
              .notBefore(Date.today)
              .notAfter(Date.today + 90day)
              .sign

    verifyNotNull(cert)
    verifyEq(cert.subject, "CN=Fantom")
    certSans := cert.subjectAltNames

    verifyEq(certSans.size, 7)
    verifyEq(((San)certSans[0]).type, SanType.dNSName)
    verifyTrue(((San)certSans[0]).val is Str)
    verifyEq(((San)certSans[0]).val, "san-test.fantom.org")
    verifyEq(((San)certSans[1]).type, SanType.dNSName)
    verifyTrue(((San)certSans[1]).val is Str)
    verifyEq(((San)certSans[1]).val, "www.san-test.fantom.org")
    verifyEq(((San)certSans[2]).type, SanType.iPAddress)
    verifyTrue(((San)certSans[2]).val is IpAddr)
    verifyEq(((San)certSans[2]).val, IpAddr("192.168.1.1"))
    verifyEq(((San)certSans[3]).type, SanType.iPAddress)
    verifyTrue(((San)certSans[3]).val is IpAddr)
    verifyEq(((San)certSans[3]).val, IpAddr("192.168.1.2"))
    verifyEq(((San)certSans[4]).type, SanType.rfc822Name)
    verifyTrue(((San)certSans[4]).val is Str)
    verifyEq(((San)certSans[4]).val, "user@fantom.org")
    verifyEq(((San)certSans[5]).type, SanType.uniformResourceIdentifier)
    verifyTrue(((San)certSans[5]).val is Str)
    verifyEq(((San)certSans[5]).val, "https://fantom.org/doc")
    verifyEq(((San)certSans[6]).type, SanType.uniformResourceIdentifier)
    verifyTrue(((San)certSans[6]).val is Str)
    verifyEq(((San)certSans[6]).val, "https://fantom.org")
  }

}