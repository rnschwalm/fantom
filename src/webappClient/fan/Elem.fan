//
// Copyright (c) 2009, Brian Frank and Andy Frank
// Licensed under the Academic Free License version 3.0
//
// History:
//   8 Jan 09  Andy Frank  Creation
//

**
** Elem models a DOM element object.
**
@javascript
class Elem
{

//////////////////////////////////////////////////////////////////////////
// Constructors
//////////////////////////////////////////////////////////////////////////

  new make(Obj obj) {}

//////////////////////////////////////////////////////////////////////////
// Attributes
//////////////////////////////////////////////////////////////////////////

  **
  ** Get the tag name for this element.
  **
  Str tagName() { return "" }

  **
  ** The id for this element.
  **
  Str id

  **
  ** The name attribute for this element.
  **
  Str name

  **
  ** The CSS class name(s) for this element.
  **
  Str className

  **
  ** Return true if this element has the given CSS class name,
  ** or false if it does not.
  **
  Bool hasClassName(Str className) { return false }

  **
  ** Add the given CSS class name to this element.  If this
  ** element already contains the given class name, then this
  ** method does nothing. Returns this.
  **
  This addClassName(Str className) { return this }

  **
  ** Remove the given CSS class name to this element. If this
  ** element does not have the given class name, this method
  ** does nothing. Returns this.
  **
  This removeClassName(Str className) { return this }

  **
  ** Get the style object for this element.
  **
  Obj style() { return "" }

  **
  ** The HTML markup contained in this element.
  **
  Str html

  **
  ** The value attribute for this element, or null if one
  ** does not exist.  This is typically only valid for form
  ** elements.
  **
  Obj? value

  **
  ** The checked attribute for this element, or null if one
  ** does not exist.  This is typically only valid for some
  ** form elements.
  **
  Bool? checked

  **
  ** Get an attribute by name.  If not found return
  ** the specificed default value.
  **
  Obj? get(Str name, Obj? def := null) { return null }

  **
  ** Set an attribute to the given value.
  **
  Void set(Str name, Obj? val) {}

//////////////////////////////////////////////////////////////////////////
// Size
//////////////////////////////////////////////////////////////////////////

  **
  ** The x position relative to the parent element in pixels.
  **
  Int x() { return 0 }

  **
  ** The y position relative to the parent element in pixels.
  **
  Int y() { return 0 }

  **
  ** The width of this element in pixels.
  **
  Int w() { return 0 }

  **
  ** The height of this element in pixels.
  **
  Int h() { return 0 }

//////////////////////////////////////////////////////////////////////////
// Tree
//////////////////////////////////////////////////////////////////////////

  **
  ** Get the parent Elem of this element, or null if
  ** this element has no parent.
  **
  Elem? parent() { return null }

  **
  ** Get the child nodes of this element.
  **
  Elem[] children() { return Elem[,] }

  **
  ** Get the previous sibling to this element, or null
  ** if this is the first element under its parent.
  **
  Elem? prev() { return null }

  **
  ** Get the next sibling to this element, or null if
  ** this is the last element under its parent.
  **
  Elem? next() { return null }

  **
  ** Add a new element as a child to this element. Return this.
  **
  This add(Elem child) { return this }

  **
  ** Remove a child element from this element. Return this.
  **
  This remove(Elem child) { return this }

//////////////////////////////////////////////////////////////////////////
// Focus
//////////////////////////////////////////////////////////////////////////

  **
  ** Request keyboard focus on this elem.
  **
  Void focus() {}

//////////////////////////////////////////////////////////////////////////
// Find
//////////////////////////////////////////////////////////////////////////

  **
  ** Return the first descendant for which c returns true.
  ** Return null if no element returns true.
  **
  Elem? find(|Elem e->Bool| c) { return null }

  **
  ** Return a list of all descendants for which c returns
  ** true.  Return an empty list if no element returns true.
  **
  Elem[] findAll(|Elem e->Bool| c) { return Elem[,] }

//////////////////////////////////////////////////////////////////////////
// Events
//////////////////////////////////////////////////////////////////////////

  **
  ** Attach an event handler to the given event on this element.
  **
  Void onEvent(Str type, |Event e| handler) {}

}