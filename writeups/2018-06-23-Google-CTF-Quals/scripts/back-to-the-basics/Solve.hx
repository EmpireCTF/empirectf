import haxe.io.Bytes;
import sys.io.File;

using StringTools;

class Solve {
  public static function main():Void {
    var program = Program.load("crackme.prg");
    var pos = program.loadAt;
    var blocks:Array<Block> = [];
    while (pos < program.loadAt + program.loaded) {
      var line = Line.fromMemory(program.memory, pos);
      var dec = line.detokenise();
      if (dec.startsWith("ES = ")) {
        var es = Std.parseInt(dec.substr(5, 5));
        var ee = Std.parseInt(dec.substr(18, 5));
        var ek = Std.parseInt(dec.substr(31, 3));
        for (i in es...ee + 1) {
          program.memory.set(i, (program.memory.get(i) + ek) & 0xFF);
        }
        blocks.push({es: es, ee: ee, v: 0, ps: [], g: 0});
      }
      var last = blocks.length > 0 ? blocks[blocks.length - 1] : null;
      if (last != null && line.address >= last.es && line.address <= last.ee) {
        if (dec.startsWith("V = ")) {
          var vval = dec.substr(4, dec.indexOf(":") - 4).split("-");
          last.v = Std.parseFloat(vval[0]);
          if (vval.length == 2) last.v -= Std.parseFloat(vval[1]);
        } else if (dec.startsWith("G = ")) {
          last.g = Std.parseFloat(dec.substr(4));
        } else if (dec.startsWith("IF B")) {
          last.ps.push(Std.parseFloat(dec.substr(dec.indexOf(" = ") + 3)));
        }
      }
      Sys.println(line.toString());
      pos += line.data.length + 5;
    }
    var bits = [];
    for (b in blocks) {
      var bestDist = 10000.0;
      var bestBits = [];
      for (i in 0...8192) {
        var sum = b.v;
        var curBits = [ for (bit in 0...13) {
            if ((i >> bit) & 1 == 1) {
              sum += b.ps[bit];
              1;
            } else 0;
          } ];
        var dist = Math.abs(b.g - sum);
        if (dist < bestDist) {
          bestDist = dist;
          bestBits = curBits;
        }
      }
      bits = bits.concat(bestBits);
    }
    Sys.print("PASSWORD: ");
    for (i in 0...30) {
      var val = 0;
      for (j in 0...8) {
        val = val | (bits[i * 8 + j] << j);
      }
      Sys.print(String.fromCharCode(val));
    }
    Sys.println("");
  }
}

typedef Block = {
     es:Int
    ,ee:Int
    ,v:Float
    ,g:Float
    ,ps:Array<Float>
  };
