class SprintSolve {
  public static function main():Void {
    var flag = sys.io.File.getBytes("sprint-data.bin").sub(0xF10C, 39);

    // brute force
    /*
    var adds = [ for (i in 0...4) for (j in 0...4) i | (i << 2) | (j << 4) | (j << 6) ];
    var chars = [ for (i in 0...flag.length) [ for (a in adds) {
      var res = (flag.get(i) + a) & 0xFF;
      if (res < 0x20 || res >= 0x7F) continue;
      res;
    } ] ];
    */
    // or known password
    var password = "ddrrrrrrddrrrrrrrrddllrruullllllllddddllllllddddrrrrrrrruurrddrrddrrlluulluullddlllllllluuuurrrrrruuuuuulllllldduurrrrrrddddddllllllddddrrrrrruuddlllllluuuuuurruuddllddrrrrrruuuurrrrrruurrllddllllllddddllllllddddrrddllrruulluuuurrrrrruullrruurruuuurrrrrr";
    var chars = [ for (i in 0...flag.length) {
      var checksum = 0;
      for (j in 0...4) {
        checksum *= 4;
        checksum += (switch (password.charAt(i * 4 + j)) {
          case "u": 0;
          case "r": 1;
          case "d": 2;
          case "l": 3;
          case _: throw "!";
        });
      }
      [(flag.get(i) + checksum) & 0xFF];
    } ];

    // print
    for (off in 0...16) {
      var printed = false;
      for (i in 0...flag.length) {
        if (off >= chars[i].length) {
          Sys.print(" ");
        } else {
          Sys.print(String.fromCharCode(chars[i][off]));
          printed = true;
        }
      }
      if (!printed) break;
      Sys.println("");
    }
  }
}
