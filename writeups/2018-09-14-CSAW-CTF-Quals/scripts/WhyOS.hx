// with console.log in the cwd
// $ haxe --run WhyOS
// but for performance reasons maybe compile to C++ first:
// $ haxe -main WhyOS -cpp whyos
// $ whyos/WhyOS

import sys.io.*;

class WhyOS {
  public static function main():Void {
    var f = File.read("console.log");
    var progs = new Map<String, FileOutput>();
    var lastProg = null;
    while (true) {
      var line = (try f.readLine() catch (e:Dynamic) break);
      var msgType = line.substr(0, 7);
      if (msgType == "default" || msgType == "error  " || msgType == "fault  ") {
        var endProg = line.indexOf(" ", 32);
        if (endProg == -1) endProg = line.length;
        var prog = line.substr(32, endProg - 32);
        if (!progs.exists(prog)) {
          progs[prog] = File.write('console-$prog.log');
        }
        lastProg = progs[prog];
      }
      lastProg.writeString(line + "\n");
    }
    for (p in progs) p.close();
  }
}
