// haxe --run Fringe
// with fringe.cc.blob in the cwd

import haxe.io.*;
import sys.io.*;

using haxe.Int64;

class Fringe {
  public static function main():Void {
    var inp = File.read("fringe.cc.blob");
    var created:Array<Array<String>> = [];
    
    function pUI8():Int return inp.readByte();
    function pUI16():Int return inp.readUInt16();
    function pI32():Int return inp.readInt32();
    function pUI32():UInt return pI32();
    function pUI64():Int64 return Int64.make(pI32(), pI32());
    function pUI():Int64 {
      var x = pUI8();
      if (x < 253) return x;
      if (x == 253) return pUI16();
      if (x == 254) return pUI32();
      return pUI64();
    }
    function pStr():String {
      var r = new BytesBuffer();
      while (true) {
        var b = pUI8();
        if (b == 0) break;
        r.addByte(b);
      }
      return r.getBytes().toString();
    }
    function pArr<T>(fn:Void->T):Array<T> {
      var size = pUI().low;
      return [ for (i in 0...size) fn() ];
    }
    function pMap<T, U>(fnK:Void->T, fnV:Void->U):Array<{k:T, v:U}> {
      var size = pUI().low;
      return [ for (i in 0...size) { k: fnK(), v: fnV() } ];
    }
    function pMaybe(fn:Void->Dynamic):Dynamic {
      var hasValue = pUI8() != 0;
      if (hasValue) return fn();
      else return null;
    }
    function pSeq(fns:Array<Void->Dynamic>):Array<Dynamic> {
      return [ for (f in fns) f() ];
    }
    function pRange():Dynamic {
      return {
        startLine: pUI(),
        startColumn: pUI(),
        endLine: pUI(),
        endColumn: pUI()
      };
    }
    function pRef():Dynamic {
      return {
        range: pRange(),
        usr: pUI(),
        symbolKind: pUI(),
        role: pUI()
      };
    }
    function pUse():Dynamic {
      return {
        ref: pRef(),
        fileId: pUI()
      }
    }
    function pIndexFunc():Dynamic {
      return {
        detailedName: pStr(),
        qualNameOffset: pUI(),
        shortNameOffset: pUI(),
        shortNameSize: pUI(),
        lsSymbolKind: pUI8(),
        storage: pUI(),
        hover: pStr(),
        comments: pStr(),
        declarations: pArr(pUse),
        spell: pMaybe(pUse),
        extent: pMaybe(pUse),
        bases: pArr(pUI),
        derived: pArr(pUI),
        vars: pArr(pUI),
        uses: pArr(pUse),
        callees: pArr(pRef)
      };
    }
    function pIndexType():Dynamic {
      return {
        detailedName: pStr(),
        qualNameOffset: pUI(),
        shortNameOffset: pUI(),
        shortNameSize: pUI(),
        lsSymbolKind: pUI8(),
        hover: pStr(),
        comments: pStr(),
        declarations: pArr(pUse),
        spell: pMaybe(pUse),
        extent: pMaybe(pUse),
        aliasOf: pUI(),
        bases: pArr(pUI),
        derived: pArr(pUI),
        types: pArr(pUI),
        funcs: pArr(pUI),
        vars: pMap(pUI, pUI),
        instances: pArr(pUI),
        uses: pArr(pUse)
      };
    }
    function pIndexVar():Dynamic {
      return {
        detailedName: pStr(),
        qualNameOffset: pUI(),
        shortNameOffset: pUI(),
        shortNameSize: pUI(),
        hover: pStr(),
        comments: pStr(),
        declarations: pArr(pUse),
        spell: pMaybe(pUse),
        extent: pMaybe(pUse),
        type: pUI(),
        uses: pArr(pUse),
        lsSymbolKind: pUI8(),
        storage: pUI()
      };
    }
    
    function outUse(ext:Use, data:String):Void {
      if (ext == null) return;
      if (ext.ref.range.startLine < 0 || ext.ref.range.startLine > 256
        ||ext.ref.range.startColumn < 0 || ext.ref.range.startColumn > 256
        ||ext.ref.range.endLine < 0 || ext.ref.range.endLine > 256
        ||ext.ref.range.endColumn < 0 || ext.ref.range.endColumn > 256) throw "oob";
      if (ext.ref.range.startLine != ext.ref.range.endLine) return;
      var sl = ext.ref.range.startLine.low >> 1;
      var sc = ext.ref.range.startColumn.low >> 1;
      var el = ext.ref.range.endLine.low >> 1;
      var ec = ext.ref.range.endColumn.low >> 1;
      while (el >= created.length || sl >= created.length) created.push([]);
      while (ec >= created[sl].length) created[sl].push(" ");
      var i = 0;
      for (o in sc...ec) created[sl][o] = data.charAt(i++);
    }
    function outMember(v:Dynamic):Void {
      var vc:{
          detailedName:String,
          shortNameOffset:Int64,
          shortNameSize:Int64,
          ?extent:Use,
          ?spell:Use,
          uses:Array<Use>
        } = (cast v);
      var shortName:String = vc.detailedName.substr(vc.shortNameOffset.low >> 1, vc.shortNameSize.low >> 1);
      outUse(vc.spell, shortName);
    }
    
    /* major */           pUI();
    /* minor */           pUI();
    /* last_write_time */ pUI();
    /* language */        pUI();
    /* lid2path */        pStr();
    /* import_file */     pStr();
    /* args */            pArr(pStr);
    /* dependencies */    pMap(pStr, pUI);
    /* includes */        pArr(pSeq.bind([pUI, pStr]));
    /* skipped_ranges */  pArr(pRange);
    /* usr2func */        pMap(pUI, pIndexFunc).map(kv -> outMember(kv.v));
    /* usr2type */        pMap(pUI, pIndexType).map(kv -> outMember(kv.v));
    /* usr2var */         pMap(pUI, pIndexVar).map(kv -> outMember(kv.v));
    trace(created.map(l -> l.join("")).join("\n"));
    // blesswodwhoisinhk
  }
}

typedef Use = {
    ref:{
      range:{
        startLine:Int64,
        startColumn:Int64,
        endLine:Int64,
        endColumn:Int64
      },
      usr:Int64,
      symbolKind:Int64,
      role:Int64
    },
    fileId:Int
  };
