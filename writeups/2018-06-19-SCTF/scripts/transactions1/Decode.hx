// haxe --run Decode
// with data.csv in cwd

import haxe.io.Bytes;

using StringTools;

class Decode {
  public static function main():Void {
    var lines = sys.io.File.getContent("data.csv").split("\n");
    lines.shift();
    var cap = lines.map(l -> l.split(", ").map(Std.parseInt));
    var lastClk = 0;
    var lastData = 0;
    var mode = "";
    var dataBuf = [];
    var outCounter = 0;
    var psc = [];
    inline function lsbInt(bits:Array<Int>):Int {
      return bits[0] | (bits[1] << 1) | (bits[2] << 2) | (bits[3] << 3)
         | (bits[4] << 4) | (bits[5] << 5) | (bits[6] << 6) | (bits[7] << 7);
    }
    for (d in cap) {
      if (d[0] < 0) continue;
      var clk = d[1];
      var data = d[2];
      var dataFall = data < lastData;
      var dataRise = data > lastData;
      var clkH = clk > 0;
      switch (mode) {
        case "":
        if (dataFall && clkH) {
          mode = "command";
          dataBuf = [];
        }
        case "command":
        if (dataRise && clkH) {
          var control = lsbInt(dataBuf.slice(0, 8));
          var address = lsbInt(dataBuf.slice(8, 16));
          var data = lsbInt(dataBuf.slice(16, 24));
          Sys.println("\ncommand: " + switch (control) {
              case 48: outCounter = (256 - address) * 8 + 1; mode = "outgoing"; "read main memory";
              case 56: mode = "processing"; "update main memory";
              case 52: outCounter = 32 + 1; mode = "outgoing"; "read protection memory";
              case 60: mode = "processing"; "write protection memory";
              case 49: outCounter = 32 + 1; mode = "outgoing"; "read security memory";
              case 57: mode = "processing"; "update security memory";
              case 51: psc.push(data); mode = "processing"; "compare verification data";
              case _: mode = ""; "unknown";
            });
          if (mode == "processing") outCounter = 0;
          Sys.println('address: $address');
          Sys.println('data:    ${data.hex(2)}');
        } else if (clkH) {
          dataBuf.push(data);
        }
        case "outgoing":
        if (clkH) {
          dataBuf.push(data);
          outCounter--;
          if (outCounter <= 0) {
            Sys.println('${dataBuf.length} bits transferred');
            mode = "";
          }
        }
        case "processing":
        if (clkH) outCounter++;
        if (dataRise) {
          Sys.println('processing for ${outCounter} cycles');
          mode = "";
        }
      }
      lastClk = clk;
      lastData = data;
    }
    Sys.println("");
    Sys.println('PSC: ${psc[0].hex(2)} ${psc[1].hex(2)} ${psc[2].hex(2)}');
  }
}
