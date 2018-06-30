using StringTools;

class Codes {
  public static function main() {
    var wires = [ for (i in 0...8) new Wire(3 + i * 2, 4 + i * 2) ];
    var nextTS = 0.0;
    var last = null;
    var lastTS = -100.0;
    while (nextTS < 20.01) {
      var values = [ for (w in wires) 1 - w.at(nextTS) ];
      var keycode = values[0] | (values[1] << 1) | (values[2] << 2)
         | (values[3] << 3) | (values[4] << 4) | (values[5] << 5);
      var current = POKEY.MAP[keycode];
      if (values[6] == 1 && current != null) {
        if (last != current && nextTS - lastTS > .1) {
          Sys.print(current + " ");
          last = current;
          lastTS = nextTS;
        }
      }
      nextTS += (1 / 15700);
    }
  }
}
