import sys.io.File;

using StringTools;

class SprintAnalyse {
  static final RE_IF = ~/^if \((reg[A-Z])\) goto (0x[0-9A-F]+) else goto (0x[0-9A-F]+)$/;
  static final RE_SET = ~/^(reg[A-Z])  = /;
  static final RE_SET_DEREF = ~/^\*(reg[A-Z]) = /;
  static final RE_GOTO = ~/^goto (0x[0-9A-F]+)$/;

  public static function main():Void {
    // parse the pseudo assembly
    var last:Ins = null;
    var code = [ for (l in File.getContent("sprint-assembly.txt").split("\n")) {
      if (l == "") continue;
      var address = Std.parseInt(l.substr(0, 6));
      l = l.substr(8);
      function reg(str:String):Reg {
        return str.charCodeAt(3) - "A".code;
      }
      var addr = Std.parseInt;
      function sum(str:String):Array<OpSum> {
        return [ for (s in str.split(" + ")) {
          if (s.startsWith("*reg")) {
            OSRegDeref(reg(s.substr(1)));
          } else if (s.startsWith("reg")) {
            OSReg(reg(s));
          } else if (s.startsWith("0x")) {
            OSConst(addr(s));
          } else throw "invalid sum operand";
        } ];
      }
      var op = (if (RE_IF.match(l)) {
        OIf(reg(RE_IF.matched(1)), addr(RE_IF.matched(2)), addr(RE_IF.matched(3)));
      } else if (RE_SET.match(l)) {
        OSet(reg(RE_SET.matched(1)), sum(RE_SET.matchedRight()));
      } else if (RE_SET_DEREF.match(l)) {
        OSetDeref(reg(RE_SET_DEREF.matched(1)), sum(RE_SET_DEREF.matchedRight()));
      } else if (RE_GOTO.match(l)) {
        OGoto(addr(RE_GOTO.matched(1)));
      } else if (l == "halt") {
        OHalt;
      } else throw "invalid instruction");
      var ins = {address: address, next: null, op: op};
      if (last != null) last.next = ins;
      last = ins;
    } ];
    // split code into blocks on jumps and jump destinations
    var blocks:Map<Int, InsBlock> = [];
    function ensureBlock(addr:Int):InsBlock {
      if (!blocks.exists(addr)) {
        blocks[addr] = {
          address: addr,
          code: [],
          jumpSources: [],
          jumpDests: [],
          regReads: [],
          regWrites: [],
          varInitial: [],
          varFinal: [],
        };
      }
      return blocks[addr];
    }
    {
      var current:InsBlock = null;
      for (ins in code) {
        switch (ins.op) {
          case OIf(_, gotoT, gotoE):
            ensureBlock(gotoT);
            ensureBlock(gotoE);
          case OGoto(goto):
            ensureBlock(goto);
          case _:
        }
      }
      var current = ensureBlock(0);
      for (ins in code) {
        if (blocks.exists(ins.address)) {
          current = blocks[ins.address];
        }
        current.code.push(ins);
        switch (ins.op) {
          case OIf(_, gotoT, gotoE):
            blocks[gotoT].jumpSources.push(current);
            blocks[gotoE].jumpSources.push(current);
            current.jumpDests.push(blocks[gotoT]);
            current.jumpDests.push(blocks[gotoE]);
          case OGoto(goto):
            blocks[goto].jumpSources.push(current);
            current.jumpDests.push(blocks[goto]);
          case _:
        }
      }
      for (block in blocks) {
        var last = block.code[block.code.length - 1];
        switch (last.op) {
          case OSet(_, _) | OSetDeref(_, _):
            if (last.next != null && blocks.exists(last.next.address)) {
              blocks[last.next.address].jumpSources.push(block);
              block.jumpDests.push(blocks[last.next.address]);
            }
          case _:
        }
      }
    };
    // cache register reads/writes
    for (block in blocks) {
      block.regReads = OpTools.blockReads(block);
      block.regWrites = OpTools.blockWrites(block);
    }
    ensureBlock(-1).regWrites = [ for (reg in 0...10) reg ];
    // deterministic order of block iteration
    var blockAddresses = [ for (b in blocks) b.address ];
    blockAddresses.sort(Reflect.compare);
    // print blocks
    /*{
      for (a in blockAddresses) {
        var block = blocks[a];
        Sys.println('block ${block.address.hex(4)}:');
        Sys.println('  reads:  ${block.regReads}');
        Sys.println('  writes: ${block.regWrites}');
      }
    };*/
    // infer variables from registers
    for (a in blockAddresses) {
      var block = blocks[a];
      block.varInitial = block.regReads.map(Var.new);
      block.varFinal = block.regWrites.map(Var.new);
    }
    for (a in blockAddresses) {
      var block = blocks[a];
      for (v in block.varFinal) {
        var visited:Map<Int, Bool> = [];
        var queue = block.jumpDests.copy();
        while (queue.length > 0) {
          var cur = queue.shift();
          var rv = cur.regReads.indexOf(v.reg);
          if (rv != -1) cur.varInitial[rv] = v.unify(cur.varInitial[rv]);
          var wv = cur.regWrites.indexOf(v.reg);
          if (wv != -1) continue;
          for (out in cur.jumpDests) {
            if (visited.exists(out.address)) continue;
            visited[out.address] = true;
            queue.push(out);
          }
        }
      }
    }
    // output code with inferred variables
    var idMapping:Map<Int, Int> = [];
    var renumCounter = 0;
    function renumber(v:Var):Int {
      // return v.id;
      if (!idMapping.exists(v.id)) {
        idMapping[v.id] = renumCounter++;
      }
      return idMapping[v.id];
    }
    for (a in blockAddresses) {
      if (a == -1) continue;
      var block = blocks[a];
      Sys.println('0x${a.hex(4)}: (from ${[ for (s in block.jumpSources) '0x${s.address.hex(4)}' ].join(", ")})');
      // Sys.println(' (regs r ${block.regReads.join(", ")})');
      // Sys.println(' (regs w ${block.regWrites.join(", ")})');
      // Sys.println(' (vars i ${block.varInitial.map(v -> '${v.id}(${v.reg})').join(", ")})');
      // Sys.println(' (vars f ${block.varFinal.map(v -> '${v.id}(${v.reg})').join(", ")})');
      var varCur = [ for (i in 0...block.regReads.length) block.regReads[i] => block.varInitial[i] ];
      function read(reg:Reg):String {
        return 'var${renumber(varCur[reg])}';
      }
      function write(reg:Reg):String {
        varCur[reg] = block.varFinal[block.regWrites.indexOf(reg)];
        return 'var${renumber(varCur[reg])}';
      }
      for (ins in block.code) {
        //Sys.print('  0x${ins.address.hex(4)}: ');
        Sys.print("  ");
        Sys.println(switch (ins.op) {
          case OIf(cond, gotoT, gotoE): 'if (${read(cond)}) goto 0x${gotoT.hex(4)} else goto 0x${gotoE.hex(4)}';
          case OSet(dest, source):
            var source = [ for (s in source) {
              switch (s) {
                case OSConst(c): '0x${c.hex(4)}';
                case OSReg(r): read(r);
                case OSRegDeref(r): '[${read(r)}]';
              }
            } ];
            '${write(dest)} = ${source.join(" + ")}';
          case OSetDeref(dest, source):
            var source = [ for (s in source) {
              switch (s) {
                case OSConst(c): '0x${c.hex(4)}';
                case OSReg(r): read(r);
                case OSRegDeref(r): '[${read(r)}]';
              }
            } ];
            '[${read(dest)}] = ${source.join(" + ")}';
          case OGoto(goto): 'goto 0x${goto.hex(4)}';
          case OHalt: "halt";
        });
      }
      Sys.println("");
    }
  }
}

typedef InsBlock = {
  address:Int,
  code:Array<Ins>,
  jumpSources:Array<InsBlock>,
  jumpDests:Array<InsBlock>,
  regReads:Array<Reg>,
  regWrites:Array<Reg>,
  varInitial:Array<Var>,
  varFinal:Array<Var>,
};

typedef Ins = {
  address:Int,
  next:Ins,
  op:Op
};

typedef Reg = Int;

class Var {
  public static var counter = 0;
  public static var unique = 0;

  public var id:Int;
  public var reg:Int;

  public function new(reg:Int) {
    id = counter++;
    unique++;
    this.reg = reg;
  }

  public function unify(other:Var):Var {
    if (id == other.id) return this;
    var min = id < other.id ? id : other.id;
    unique--;
    id = min;
    other.id = min;
    return this;
  }
}

@:using(SprintAnalyse.OpTools)
enum Op {
  OIf(cond:Reg, gotoT:Int, gotoE:Int);
  OSet(dest:Reg, source:Array<OpSum>);
  OSetDeref(dest:Reg, source:Array<OpSum>);
  OGoto(goto:Int);
  OHalt;
}

enum OpSum {
  OSConst(_:Int);
  OSReg(_:Reg);
  OSRegDeref(_:Reg);
}

class OpTools {
  public static function reads(op:Op):Array<Reg> {
    return (switch (op) {
      case OIf(cond, _, _): [cond];
      case OSet(_, source): readsS(source);
      case OSetDeref(dest, source): [dest].concat(readsS(source));
      case _: [];
    });
  }

  public static function writes(op:Op):Array<Reg> {
    return (switch (op) {
      case OSet(dest, _): [dest];
      case _: [];
    });
  }

  public static function readsS(ss:Array<OpSum>):Array<Reg> {
    return [ for (s in ss) switch (s) {
      case OSConst(_): continue;
      case OSReg(reg) | OSRegDeref(reg): reg;
    } ];
  }

  public static function blockReads(block:InsBlock):Array<Reg> {
    var written:Map<Reg, Bool> = [];
    var reads:Map<Reg, Bool> = [];
    for (ins in block.code) {
      for (read in ins.op.reads()) {
        if (written.exists(read)) continue;
        reads[read] = true;
      }
      for (write in ins.op.writes()) {
        written[write] = true;
      }
    }
    return [ for (reg in 0...10) if (reads.exists(reg)) reg ];
  }

  public static function blockWrites(block:InsBlock):Array<Reg> {
    var written:Map<Reg, Bool> = [];
    for (ins in block.code) {
      for (write in ins.op.writes()) {
        written[write] = true;
      }
    }
    return [ for (reg in 0...10) if (written.exists(reg)) reg ];
  }
}
