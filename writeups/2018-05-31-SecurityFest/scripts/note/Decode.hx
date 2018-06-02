// run with haxe --run Decode
// assuming emsg.txt in the cwd

using StringTools;
using sys.io.File;

class Decode {
  public static function main() {
    // get cipher text
    var cipher = "emsg.txt".getContent().split(" ")
      .filter(c -> c != "").map(Std.parseInt);
    Sys.println("Cipher text:");
    Sys.println({ var i = -25; [ while (i < cipher.length) { i += 25; cipher.slice(i, i + 25).join(" "); } ].join("\n"); });
    
    // find additive key
    inline function validPoly(n:Int):Bool {
      var x = n % 10;
      var y = Std.int(n / 10);
      return (x >= 1 && x <= 5) && (y >= 1 && y <= 5);
    }
    var key:Array<Int> = null;
    for (keyLen in 1...24) {
      var columns = [ for (i in 0...keyLen) [] ];
      for (i in 0...cipher.length) columns[i % keyLen].push(cipher[i]);
      var candidate = [ for (keyPos in 0...keyLen) [ for (keyVal in 11...56) {
          if (!validPoly(keyVal)) continue;
          var keyValPossible = true;
          for (c in columns[keyPos]) {
            if (!validPoly(c - keyVal)) {
              keyValPossible = false;
              break;
            }
          }
          if (!keyValPossible) continue;
          keyVal;
        } ] ];
      var keyPossible = true;
      for (k in candidate) if (k.length != 1) {
        keyPossible = false;
        break;
      }
      if (!keyPossible) continue;
      key = candidate.map(c -> c[0]);
      break;
    }
    Sys.println('Shortest valid additive key is: ' + key.join(", "));
    
    // remove additive key from cipher
    cipher = [ for (i in 0...cipher.length) cipher[i] - key[i % key.length] ];
    Sys.println("Cipher text without additive key:");
    Sys.println({ var i = -25; [ while (i < cipher.length) { i += 25; cipher.slice(i, i + 25).join(" "); } ].join("\n"); });
    
    // initialise polybius square
    var polybius = "a b c d e f g h i k l m n o p q r s t u v w x y z".split(" ");
    inline function rx(c:Int):Int return (c % 10) - 1;
    inline function ry(c:Int):Int return Std.int(c / 10) - 1;
    inline function rc(c:Int):Int return ry(c) * 5 + rx(c);
    
    // crib trigram: THE
    var trigrams = new Map<Int, Int>();
    for (i in 0...cipher.length - 2) {
      var trigram = cipher[i] * 10000 + cipher[i + 1] * 100 + cipher[i + 2];
      if (!trigrams.exists(trigram)) trigrams[trigram] = 0;
      trigrams[trigram]++;
    }
    var trigArr = [ for (k in trigrams.keys()) {k: k, f: trigrams[k]} ];
    trigArr.sort((a, b) -> b.f - a.f);
    var the = trigArr[0].k;
    Sys.println("THE in cipher is probably: " + the);
    polybius[rc(Std.int(the / 10000)      )] = "T";
    polybius[rc(Std.int(the / 100  ) % 100)] = "H";
    polybius[rc(Std.int(the        ) % 100)] = "E";
    
    // frequency chart
    var freqs = [ for (i in 0...25) 0 ];
    for (c in cipher) {
      freqs[rc(c)]++;
    }
    
    // interactive decoding
    function printSquare<T>(s:Array<T>):Void {
      var i = 0;
      for (y in 0...5) {
        for (x in 0...5) {
          Sys.print(Std.string(s[i++]).lpad(" ", 3));
        }
        Sys.println("");
      }
    }
    Sys.println("--- Interactive decode mode ---");
    while (true) {
      Sys.println("Current square:");
      printSquare(polybius);
      Sys.println("Frequency chart:");
      printSquare(freqs);
      Sys.println("Current plain text:");
      for (c in cipher) {
        Sys.print(polybius[rc(c)]);
      }
      Sys.println("");
      Sys.print("Replace: ");
      var find = Sys.stdin().readLine();
      if (find == "") break;
      Sys.print("With:    ");
      var replace = Sys.stdin().readLine().toUpperCase();
      if (replace == "") continue;
      var fi = polybius.indexOf(find);
      if (fi != -1) polybius[fi] = replace;
    }
  }
}
