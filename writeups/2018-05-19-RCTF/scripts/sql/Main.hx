// compile with haxe -main Main -neko vm.n
// then with sql.txt in the cwd, run neko vm.n

import haxe.io.Bytes;
import haxe.Int64;

class Main {
  public static function main() {
    var ops = sys.io.File.getContent("sql.txt").split("\n").slice(4).map(l -> l.split("|"));
    var cpos = 0;
    var regs:Array<Reg> = [ for (i in 0...256) Undefined ];
    var pi = Std.parseInt;
    var l = Sys.println;
    var le = Sys.print;
    var flagKnown = "????????????????????????????????????????";
    function regW(reg:Int, val:Reg):Void {
      if (reg >= regs.length) throw "not enough regs";
      regs[reg] = val;
    }
    function regWSI64(reg:Int, val:Int64):Void regs[reg] = SI64(val);
    function regRSI64(reg:Int):Int64 return switch (regs[reg]) {
        case SI64(v): v;
        case _: throw "not an int reg"; 0;
      };
    function regWString(reg:Int, val:String):Void regs[reg] = String(val);
    function dumpReg(r:Reg):Void l(switch (r) {
        case Undefined: "u";
        case Null: "n";
        case SI64(v): Int64.toStr(v);
        case String(s): s;
        case Flag: "Flag";
        case FlagSub(start, len): 'FlagSub($start, $len)';
      });
    function dump():Void regs.map(dumpReg);
    function cmpReg(a:Reg, b:Reg, shouldEq:Bool):Bool {
      le(' A: '); dumpReg(a);
      le(' B: '); dumpReg(b);
      return (switch [a, b] {
          case [String(aa), String(bb)]: aa == bb;
          case [String(aa), Flag] | [Flag, String(aa)]: if (shouldEq) flagKnown = aa; shouldEq;
          case [String(aa), FlagSub(s, len)] | [FlagSub(s, len), String(aa)]:
          var as = s - 1;
          if (shouldEq) flagKnown = flagKnown.substr(0, as) + aa + flagKnown.substr(as + len);
          l('!!! $flagKnown');
          shouldEq;
          case _: false;
        });
    }
    while (cpos < ops.length) {
      le('$cpos ');
      var cur = ops[cpos++];
      var p1 = pi(cur[2]);
      var p2 = pi(cur[3]);
      var p3 = pi(cur[4]);
      var p4 = cur[5];
      var p5 = cur[6];
      switch (cur[1]) {
        case "Column": l('r[$p3] <- [$p1][$p2]'); regW(p3, Flag);
        case "Function":
        l('r[$p3] <- $p4(' + [ for (i in 0...pi(p5)) 'r[${p2 + i}] ${p1 & (1 << i) != 0 ? "c" : "d"}' ].join(", ") + ')');
        switch (p4) {
          case "substr(3)":
          regs[p3] = (switch (regs[p2]) {
              case Flag: FlagSub(regRSI64(p2 + 1).low, regRSI64(p2 + 2).low);
              case _: l('from ${regs[p2]}'); Null;
            });
          dumpReg(regs[p3]);
          case _: l('unknown function: $p4'); Sys.exit(1);
        }
        case "Eq": l('if (r[$p1] == r[$p3]) goto $p2');
        if (cmpReg(regs[p1], regs[p3], p2 != 90)) cpos = p2;
        case "Goto": l('goto $p2'); cpos = p2;
        case "Integer": l('r[$p2] <- $p1'); regWSI64(p2, p1);
        case "Ne": l('if (r[$p1] != r[$p3]) goto $p2');
        if (!cmpReg(regs[p1], regs[p3], p2 == 90)) cpos = p2;
        case "OpenRead": l('opening ro table, root page ${p2}, ${p3 == 0 ? "main db" : "other db"}');
        case "Rewind": l('rewinding table');
        case "String8": l('r[$p2] <- $p4'); regWString(p2, p4);
        case "TableLock": l('lock table ${p4}');
        case "Trace": l('trace');
        case "Transaction": l('transaction ${p2 != 0 ? "rw" : "ro"}');
        case "VerifyCookie": l('verify cookie?');
        case _: l('unknown op: ${cur[1]}'); Sys.exit(1);
      }
    }
  }
}

enum Reg {
  Undefined;
  Null;
  SI64(v:Int64);
  String(s:String);
  Flag;
  FlagSub(start:Int, len:Int);
}
