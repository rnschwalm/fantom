//
// Copyright (c) 2012, Brian Frank and Andy Frank
// Licensed under the Academic Free License version 3.0
//
// History:
//   28 Jun 2012  Andy Frank  Creation
//

/**
 * WebTablePeer.
 */
fan.webfwt.WebTablePeer = fan.sys.Obj.$extend(fan.fwt.TablePeer);
fan.webfwt.WebTablePeer.prototype.$ctor = function(self) {}

fan.webfwt.WebTablePeer.prototype.cellPos = function(self,col,row)
{
  return this.$cellPos(self, col, row);
}