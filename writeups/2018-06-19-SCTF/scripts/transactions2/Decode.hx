using StringTools;

class Decode {
  public static function main():Void {
    var lines = sys.io.File.getContent("data.csv").split("\n");
    lines.shift();
    var cap = lines.map(l -> l.split(", ").map(Std.parseInt));
    var lastClk = 0;
    var lastData = 0;
    var lastReset = 0;
    var mode = "";
    var psc = [];
    var writes = [];
    var dataBuf = [];
    var dataCounter = 0;
    var dataSize = 0;
    inline function lsbInt(bits:Array<Int>):Int {
      var ret = 0;
      for (i in 0...bits.length) ret |= bits[i] << i;
      return ret;
    }
    inline function msbInt(bits:Array<Int>):Int {
      bits.reverse();
      var ret = 0;
      for (i in 0...bits.length) ret |= bits[i] << i;
      bits.reverse();
      return ret;
    }
    for (d in cap) {
      var clk = d[1];
      var data = d[2];
      var reset = d[3];
      var clockFall = clk < lastClk;
      var clockRise = clk > lastClk;
      var resetFall = reset < lastReset;
      var resetRise = reset > lastReset;
      var clockH = clk > 0;
      var dataL = data < 1;
      var resetL = reset < 1;
      if (resetRise) {
        dataBuf = [];
        dataCounter = 0;
        mode = "command";
      } else if (resetFall) {
        if (mode == "command") {
          Sys.println("POR");
          mode = "read";
          dataBuf = [];
          dataCounter = 0;
          dataSize = 8;
        }
      }
      switch (mode) {
        case "command":
        if (clockH) {
          dataBuf.push(data);
          dataCounter++;
          if (dataCounter == 24) {
            var control = msbInt(dataBuf.slice(0, 6));
            var address = (lsbInt(dataBuf.slice(6, 8)) << 8) | lsbInt(dataBuf.slice(8, 16)); 
            var data = lsbInt(dataBuf.slice(16, 24));
            Sys.println("\ncommand: " + switch (control) {
                case 35: mode = "program"; "write and erase with protect";
                case 51: writes.push({ address: address, data: data }); mode = "program"; "write and erase without protect";
                case 3:  mode = "program"; "write protect with data comparison";
                case 12: dataSize = 9; mode = "read"; "read data with protect";
                case 28: dataSize = 8; mode = "read"; "read data without protect";
                case 19: mode = "program"; "write error counter";
                case 44: psc.push(data); mode = "program"; "verify PSC byte";
                case _: 'unknown ${control.hex(2)}, ${d[0]}';
              });
            if (mode == "read") {
              dataCounter = -1;
              dataBuf = [];
            }
            if (mode == "program") dataCounter = 0;
            Sys.println('address: ${address}');
            Sys.println('data:    ${(data).hex(2)}');
          }
        }
        case "read":
        if (clockRise) {
          if (dataCounter >= 0) dataBuf.push(data);
          dataCounter++;
          if (dataCounter == dataSize) {
            dataCounter = 0;
            dataBuf = [];
          }
        }
        case "program":
        if (clockH) dataCounter++;
        if (clockFall && dataL && resetL) {
          Sys.println('programming for $dataCounter cycles');
          mode = "";
        }
      }
      lastClk = clk;
      lastData = data;
      lastReset = reset;
    }
    Sys.println("");
    Sys.println('PSC: ${psc[0].hex(2)} ${psc[1].hex(2)}');
    Sys.println('Write addresses: ' + [ for (a in writes) a.address.hex(2) ].join(" "));
    Sys.println('Write values:    ' + [ for (a in writes) a.data.hex(2) ].join(" "));
  }
}
