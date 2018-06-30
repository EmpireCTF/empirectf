class JS {
  public static function main():Void {
    var enc = [
        162, 215, 38, 129, 202, 180, 99, 202, 175, 172, 36, 182, 179, 180, 125,
        205, 200, 180, 84, 151, 169, 208, 56, 205, 179, 205, 124, 212, 156, 247,
        97, 200, 208, 221, 38, 155, 168, 254, 74
      ];
    var alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_@!?-".split("").map(c -> c.charCodeAt(0));
    var sol = [ for (i in 0...4) {
        var vals = [ for (val in 0...256) {
            var possible = true;
            var pos = i;
            while (pos < enc.length) {
              var dec = enc[pos] ^ val;
              if (alpha.indexOf(dec) == -1) {
                possible = false;
                break;
              }
              pos += 4;
            }
            if (!possible) continue;
            val;
          } ];
        vals[vals.length - 1];
      } ];
    Sys.println([ for (i in 0...enc.length) String.fromCharCode(enc[i] ^ sol[i % 4]) ].join(""));
  }
}
