//
// Copyright (c) 2026, Brian Frank and Andy Frank
// Licensed under the Academic Free License version 3.0
//
// History:
//   21 Apr 2026  Ross Schwalm  Creation
//

using asn1

**
** SanTest - Tests for RFC 5280 GeneralName types
**
class SanTest : CryptoTest
{

  Void testEmail()
  {
    san := San.email("user@fantom.org")

    verifyEq(((SanType)san.type).tagId, 1)
    verifyEq(san.type, SanType.rfc822Name)
    verifyEq(san.val, "user@fantom.org")
    verifyEq(san.toStr, "email:user@fantom.org")
  }

  Void testDns()
  {
    san := San.dns("example.com")

    verifyEq(((SanType)san.type).tagId, 2)
    verifyEq(san.type, SanType.dNSName)
    verifyEq(san.val, "example.com")
    verifyEq(san.toStr, "DNS:example.com")
  }

  Void testUri()
  {
    //Uri
    uri := `https://fantom.org/doc`
    san := San.uri(uri)

    verifyEq(((SanType)san.type).tagId, 6)
    verifyEq(san.type, SanType.uniformResourceIdentifier)
    verify(san.val is Str)
    verifyEq(san.val, "https://fantom.org/doc")
    verifyEq(san.toStr, "URI:https://fantom.org/doc")

    san2 := San.uri(`https://fantom.org`)
    verifyEq(san2.val, "https://fantom.org/")

    san3 := San.uri("https://fantom.org")
    verifyEq(san3.val, "https://fantom.org")
  }

  Void testIp()
  {
    san := San.ip("192.168.1.1")

    verifyEq(((SanType)san.type).tagId, 7)
    verifyEq(san.type, SanType.iPAddress)
    verifyEq(san.val, Type.find("inet::IpAddr").make(["192.168.1.1"]))
    verify(Type.find("inet::IpAddr").fits(san.val.typeof))
    verifyEq(san.toStr, "IP Address:192.168.1.1")

    san2 := San.ip(Type.find("inet::IpAddr").make(["192.168.1.2"]))

    verify(Type.find("inet::IpAddr").fits(san2.val.typeof))
    verifyEq(san2.toStr, "IP Address:192.168.1.2")
  }

  Void testRegisteredID()
  {
    //AsnOid
    oid := Asn.oid("1.2.840.113549.1.9.1") // emailAddress OID
    san := San.registeredID(oid)

    verifyEq(((SanType)san.type).tagId, 8)
    verifyEq(san.type, SanType.registeredID)
    verify(san.val is Str)
    verifyEq(san.val, "1.2.840.113549.1.9.1")
    verifyEq(san.toStr, "Registered ID:1.2.840.113549.1.9.1")

    //Str
    san2 := San.registeredID("1.2.840.113549.1.9.1")

    verifyEq(((SanType)san.type).tagId, 8)
    verifyEq(san.type, SanType.registeredID)
    verify(san.val is Str)
    verifyEq(san.val, "1.2.840.113549.1.9.1")
    verifyEq(san.toStr, "Registered ID:1.2.840.113549.1.9.1")
  }

  Void testDn()
  {
    san := San.dn("cn=fantom")

    verifyEq(((SanType)san.type).tagId, 4)
    verifyEq(san.type, SanType.directoryName)
    verify(san.val is Str)
    verifyEq(san.val, "cn=fantom")
    verifyEq(san.toStr, "DirName:cn=fantom")
  }

  Void testOther()
  {
    //TODO
  }


//////////////////////////////////////////////////////////////////////////
// Integration Tests
//////////////////////////////////////////////////////////////////////////

  Void testCsr()
  {
    openssl := Str<|-----BEGIN CERTIFICATE REQUEST-----
                    MIIDiTCCAnECAQAwZzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCFZpcmdpbmlhMREw
                    DwYDVQQHDAhSaWNobW9uZDEPMA0GA1UECgwGRmFudG9tMQwwCgYDVQQLDANEZXYx
                    EzARBgNVBAMMCmZhbnRvbS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
                    AoIBAQDZO/kv2qpVZQi4UMDz9yFd0Yg77d0gULxfJxhk8LDRqgi/NlkSZQ+VDgTP
                    h1AsxcqL1oLCv+FA45t06P5g712PrJaTQn5zlG9rjt0hCp21EN53O02dcJInFgKX
                    uF9zQVE4f6V82rY6bsPFLc3aVn5On7kuLUJVy2Y3MeQ/mxJfaInHuiOwhuAxJ8BK
                    7wKdz7I5sI21GIyfmOMJzhEEMe8OtAZjzX2v/QtxsUtTePmcKRQm823zOsCZv9b9
                    B0F1Q5Z124ASAxc6WpFMcWtrVg9qGsZVilEb3KsQdH++ZuZSVW+Uev4IQoElzt0Q
                    TvyKGVtl+jfq5xDyI09vRjQA6piHAgMBAAGggdwwgdkGCSqGSIb3DQEJDjGByzCB
                    yDCBxQYDVR0RBIG9MIG6ggpmYW50b20ub3Jngg53d3cuZmFudG9tLm9yZ4cEwKgB
                    AYEQYWRtaW5AZmFudG9tLm9yZ4YSaHR0cHM6Ly9mYW50b20ub3JniAUqAwQFBqRH
                    MEUxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZGYW50b20xDjAMBgNVBAsMBVNhbGVz
                    MRUwEwYDVQQDDAxhbHQtZGlyLW5hbWWgIAYKKwYBBAGCNxQCA6ASDBB1c2VyQGV4
                    YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAogGlPvLZvEM67ksE+3b788QLi
                    paTgDbTP388UO/ciLfoijT9BEhqpYcAznVDtxLnK8B6GkJS/EAn3azOmxognYFxv
                    ZsHVdKyzwQ0x26RdvKdYj+wQMAph/vgRgBMLCEO1y+c0nlg+1Zq7BrpzjWP3+R1t
                    EZoQjmgU5Vvy9+edqRBia5W8dGPJc0iEKN8kntnUdxL9nDHydrUrGnOs2Bg8OR+T
                    PkhgcQCiSYTRLGQK5joijNGKIBAvmj9k7cLzxLWE2bdVBC6mQOp6tVVU9HL2tOrv
                    hX5p7NtMV7J0Aj02Rgoao+Ht8DPkbzttps8yJfq/Mh2nVQuFLz2+eKdCsgCM
                    -----END CERTIFICATE REQUEST-----|>

    decodedCsr := crypto.loadPem(openssl.in) as Csr
    verify(decodedCsr.subjectAltNames.size >= 7)

    sanStrs := decodedCsr.subjectAltNames.map |san| { san.toStr }
    verifyEq(((Str)sanStrs[0]), "DNS:fantom.org")
    verifyEq(((Str)sanStrs[1]), "DNS:www.fantom.org")
    verifyEq(((Str)sanStrs[2]), "IP Address:192.168.1.1")
    verifyEq(((Str)sanStrs[3]), "email:admin@fantom.org")
    verifyEq(((Str)sanStrs[4]), "URI:https://fantom.org")
    verifyEq(((Str)sanStrs[5]), "Registered ID:1.2.3.4.5.6")
    verifyEq(((Str)sanStrs[6]), "DirName:C=US,O=Fantom,OU=Sales,CN=alt-dir-name")
    verifyEq(((Str)sanStrs[7]), "othername:<bytes>")
  }

  Void testCert()
  {
    //TODO
  }
}
