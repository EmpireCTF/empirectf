using StringTools;

class PatternFind {
  public static function main():Void {
    inline function countBits(bits:Array<Int>):Int {
      var ret = 0;
      for (b in bits) ret += b;
      return ret;
    }
    var raw = "02:00:54:42:53:6a:07:11:1b:0a:1e:48:0e:13:11:07:07:00:18:7b:2b:00:49:5e:4b:2a:13:02:19:11:38:01:1d:19:38:0e:12:12:05:3b:c0"
        .split(":")
        .map(d -> Std.parseInt('0x' + d));
    var data = raw
        .map(d -> [ for (i in 0...7) (d >> (6 - i)) & 1 ]);
    var pattern = [2, 4, 3];
    var matches = [ for (i in 0...data.length - pattern.length) {
        var match = true;
        for (j in 0...pattern.length) {
          if (countBits(data[i + j]) < pattern[j]) match = false;
        }
        match;
      } ];
    Sys.println([ for (i in 0...data.length)
        '${raw[i].hex(2)}: ${data[i]}: ${countBits(data[i])}' + (matches[i] ? " MATCH" : "")
      ].join("\n"));
  }
}
