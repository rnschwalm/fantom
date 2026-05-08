//
// Copyright (c) 2026, Brian Frank and Andy Frank
// Licensed under the Academic Free License version 3.0
//
// History:
//   16 Apr 2026 Ross Schwalm Creation
//

using asn1

**
** San defines the api for a Subject Alternative Name based on RFC 5280.
**
const class San
{

//////////////////////////////////////////////////////////////////////////
// Construction
//////////////////////////////////////////////////////////////////////////

  static new dns(Str name) { San(SanType.dNSName, name) }
  static new email(Str email) { San(SanType.rfc822Name, email) }
  static new other(Buf buf) { San(SanType.otherName, buf.toImmutable) }
  static new dn(Str dn) { San(SanType.directoryName, dn) }

  static new ip(Obj ip)
  {
    IpAddr := Type.find("inet::IpAddr")
    if (ip is Str) return San(SanType.iPAddress, IpAddr.make([ip]))
    else if (IpAddr.fits(ip.typeof)) return San(SanType.iPAddress, ip)
    throw ArgErr("Parameter must be IpAddr or Str")
  }

  static new uri(Obj uri)
  {
    //Store uri as a string to avoid trailing slash getting added
    if (uri is Str)
    {
      if (Uri.fromStr(uri).isRel) throw ArgErr("Parameter must not be a relative Uri")
      return San(SanType.uniformResourceIdentifier, uri.toStr)
    }
    else if (uri is Uri) return San.uri(uri.toStr)
    throw ArgErr("Parameter must be Uri or Str")
  }

  static new registeredID(Obj oid)
  {
    if (oid is AsnOid) return San(SanType.registeredID, ((AsnOid)oid).oidStr)
    else if (oid is Str) return San(SanType.registeredID, (Str)oid)
    throw ArgErr("Parameter must be AsnOid or Str")
  }

  private new make(SanType type, Obj val)
  {
    this.type = type
    this.val = val
  }

  ** Convenience for creating a San from a value.
  **
  ** The 'value' may be one of the following types:
  **  - 'Str':    returns San.dns
  **  - 'Uri':    returns San.uri
  **  - 'AsnOid': returns San.registeredID
  **  - 'Buf':    returns San.other
  **  - 'IpAddr': returns San.ip
  **  - 'San':    returns itself
  static new fromValue(Obj value)
  {
    if (value is Str)         return San.dns(value)
    else if (value is Uri)    return San.uri(value)
    else if (value is AsnOid) return San.registeredID((AsnOid)value)
    else if (value is Buf)    return San.other(((Buf)value).toImmutable)
    else if (value is San)    return value
    else if (Type.find("inet::IpAddr").fits(value.typeof)) return San.ip(value)
    else throw ArgErr("Unsupported value: ${value} (${value.typeof})")
  }

//////////////////////////////////////////////////////////////////////////
// Identity
//////////////////////////////////////////////////////////////////////////

  ** RFC5280 Type
  const SanType type

  ** Get the value (Str, Uri, IpAddr, AsnOid or Buf)
  const Obj val

  ** Get a friendly encoding using the format: {SanType.text}:{value}
  override Str toStr()
  {
    if (type == SanType.otherName) return "${type.text}:<bytes>"
    return "${type.text}:${val}"
  }

}

**************************************************************************
** SanType
**************************************************************************

enum class SanType
{
  otherName(0, "othername"),
  rfc822Name(1, "email"),
  dNSName(2, "DNS"),
  x400Address(3, "X400"),
  directoryName(4, "DirName"),
  ediPartyName(5, "EdiPartyName"),
  uniformResourceIdentifier(6, "URI"),
  iPAddress(7, "IP Address"),
  registeredID(8, "Registered ID")

  private new make(Int tagId, Str text)
  {
    this.text = text
    this.tagId = tagId
  }

  static SanType? fromTagId(Int tagId, Bool checked := true)
  {
    v := vals.find { it.tagId == tagId }
    if (v != null) return v
    if (checked) throw UnsupportedErr("Unsupported tag id: ${tagId}")
    return null
  }

  const Int tagId
  const Str text
}