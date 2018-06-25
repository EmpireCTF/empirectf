// haxe --run Decode
// with test.zip in the same directory

import haxe.ds.Vector;
import haxe.io.Bytes;

class Decode {
  public static function crypt(arg13:Bytes, arg14:String):Bytes {
    var v6:Int;
    var v11:Int = 0x100;
    var v4 = Bytes.ofString(arg14);
    var v7 = 0;
    var v0 = new Vector<Int>(v11);
    for (v2 in 0...v11) {
      v0[v2] = v2;
    }
    for (v2 in 0...v11) {
      v7 = (v0[v2] + v7 + v4.get(v2 % v4.length)) % 0x100;
      v6 = v0[v2];
      v0[v2] = v0[v7];
      v0[v7] = v6;
    }
    v7 = 0;
    var v8 = 0;
    var v5 = Bytes.alloc(arg13.length);
    var v3 = 0;
    var v10 = arg13.length;
    for (v9 in 0...v10) {
      var v1 = arg13.get(v9);
      v7 = (v7 + 1) % 0x100;
      v8 = (v0[v7] + v8) % 0x100;
      v6 = v0[v8];
      v0[v8] = v0[v7];
      v0[v7] = v6;
      v5.set(v3, ((v0[(v0[v7] + v0[v8]) % 0x100] ^ v1)));
      ++v3;
    }
    return v5;
  }
  
  public static function main() {
    var orig = sys.io.File.getBytes("test.zip");
    orig.set(0, 113);
    orig.set(1, 114);
    orig.set(2, 10);
    orig.set(3, 8);
    sys.io.File.saveBytes("load2.dex", crypt(orig, "E82038F4B30E810375C8365D7D2C1A3F"));
  }
}
