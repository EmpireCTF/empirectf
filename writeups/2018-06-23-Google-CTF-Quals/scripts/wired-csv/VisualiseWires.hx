using StringTools;

class VisualiseWires {
  public static function main() {
    var wires = [ for (i in 0...8) new Wire(3 + i * 2, 4 + i * 2) ];
    var nextTS = 0.0;
    for (tick in 0...20) {
      var values = [ for (w in wires) w.at(nextTS) ];
      Sys.println(values.map(v -> v == 0 ? "▌" : " ").join(""));
      nextTS += (1 / 15700);
    }
  }
}
