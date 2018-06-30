import haxe.io.Bytes;
import sys.io.File;

using StringTools;

class Lenient {
  public static function main():Void {
    var program = Program.load("crackme.prg");
    var pos = program.loadAt;
    while (pos < program.loadAt + program.loaded) {
      var line = Line.fromMemory(program.memory, pos);
      Sys.print(line.binary ? '---- <- ' : '${line.nextAddress.hex(4)} <- ');
      Sys.println(line.toString());
      pos += line.data.length + 5;
    }
  }
}
