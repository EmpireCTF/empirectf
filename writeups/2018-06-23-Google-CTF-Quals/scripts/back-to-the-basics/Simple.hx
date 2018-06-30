import haxe.io.Bytes;
import sys.io.File;

class Simple {
  public static function main():Void {
    var program = Program.load("crackme.prg");
    var pos = program.loadAt;
    while (true) {
      var line = Line.fromMemory(program.memory, pos);
      if (line.end) break;
      Sys.println(line.toString());
      pos = line.nextAddress;
    }
  }
}
