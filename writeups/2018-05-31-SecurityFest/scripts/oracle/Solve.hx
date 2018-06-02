// run with haxe --run Decode
// assuming emsg.txt in the cwd

using StringTools;
using sys.io.File;

class Solve {
  public static function main() {
    // get cipher text
    var raw = "emsg.txt".getBytes();
    var cipher = [ for (i in 0...raw.length) raw.get(i) ];
    
    // frequency chart
    var freqs = [ for (i in 0...256) 0 ];
    var bestCount = 0;
    var bestIndex = 0;
    for (c in cipher) {
      if (++freqs[c] > bestCount) {
        bestCount = freqs[c];
        bestIndex = c;
      }
    }
    
    // initialise mapping
    var map = new Map<Int, String>();
    
    // replace most common character with space
    map[bestIndex] = " ";
    
    // interactive decoding
    inline function san(s:String):String {
      var cc = s.charCodeAt(0);
      return (cc >= 0x20 && cc <= 0x7F) ? s : "%";
    }
    Sys.println("--- Interactive decode mode ---");
    while (true) {
      Sys.println("Frequency chart:");
      Sys.println("   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F");
      for (i in 0...16) {
        Sys.print("0123456789ABCDEF".split("")[i]);
        for (j in 0...16) {
          Sys.print(Std.string(freqs[i * 16 + j]).lpad(" ", 3));
        }
        Sys.println("");
      }
      Sys.println("Current plain text:");
      Sys.println("    0 1 2 3 4 5 6 7 8 9 |  0  1  2  3  4  5  6  7  8  9");
      var i = 0;
      while (i < cipher.length) {
        Sys.print(Std.string(i).lpad(" ", 3));
        for (j in i...i + 10) {
          if (j >= cipher.length) Sys.print("  ");
          else Sys.print(" " + (map.exists(cipher[j]) ? san(map[cipher[j]]) : "?"));
        }
        Sys.print(" |");
        for (j in i...i + 10) {
          if (j >= cipher.length) Sys.print("   ");
          else Sys.print(" " + cipher[j].hex(2));
        }
        Sys.println("");
        i += 10;
      }
      Sys.print("Replace pos / char: ");
      switch (Sys.stdin().readLine()) {
        case "pos":
        Sys.print("Replace (pos):   ");
        var find = Sys.stdin().readLine();
        if (find == "") continue;
        Sys.print("With (charcode): ");
        var replace = Sys.stdin().readLine();
        if (replace == "") continue;
        map[cipher[Std.parseInt(find)]] = String.fromCharCode(Std.parseInt(replace));
        case "char":
        Sys.print("Replace (charcode): ");
        var find = Sys.stdin().readLine();
        if (find == "") continue;
        Sys.print("With (charcode):    ");
        var replace = Sys.stdin().readLine();
        if (replace == "") continue;
        map[Std.parseInt(find)] = String.fromCharCode(Std.parseInt(replace));
        case _: break;
      }
    }
  }
}