using StringTools;

class RawCodes {
  public static function main() {
    var wires = [ for (i in 0...8) new Wire(3 + i * 2, 4 + i * 2) ];
    var nextTS = 0.0;
    while (nextTS < 20.01) {
      var values = [ for (w in wires) 1 - w.at(nextTS) ];
      var keycode = values[0] | (values[1] << 1) | (values[2] << 2)
         | (values[3] << 3) | (values[4] << 4) | (values[5] << 5);
      if (values[6] == 1 && POKEY.MAP[keycode] != null) {
        Sys.print(POKEY.MAP[keycode] + " ");
      }
      nextTS += (1 / 15700);
    }
  }
}
