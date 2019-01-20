// to emulate:
// haxe -D EMULATE --run Juggle
// to generate sol.xml
// haxe --run Juggle

import haxe.io.Bytes;

class Juggle {
  public static function main():Void {
    // PoC binary search using only a > comparison
    // var number = Std.int(Math.random() * 0x7FFFFF);
    // var high = 0x800000;
    // var low = 0;
    // while (high > low) {
    //   var mid = (low + high) >> 1;
    //   if (mid + 1 > number) {
    //     high = mid;
    //   } else {
    //     low = mid + 1;
    //   }
    // }
    // trace(number == low);
    
    var code:Array<Array<Ins>> = [];
    var cblock:Array<Ins> = null;
    var stack:Array<Int> = [];
    var labels = new Map<String, Int>();
    inline function op(ins:Ins) cblock.push(ins);
    inline function goto(l:String) { op(PUSHL(l)); op(PUSHI(1)); op(JMP); }
    function block(label:String, f:Void->Void):Void {
      if (labels.exists(label)) throw "duplicate block";
      labels[label] = code.length;
      cblock = [];
      f();
      code.push(cblock);
    }
    
    // binary search each chef number
    block("bsearch", () -> { // -
        op(PUSHI(0)); // (low)
#if EMULATE
        op(PUSHI(0x800000)); // (high) (low)
#else
        op(PUSHS("4294967296")); // (high) (low)
#end
        goto("loop"); // (high) (low)
      });
    
    // loop condition (continue if high > low)
    block("loop", () -> { // (high) (low)
        op(PUSHL("continue")); // (L-continue) (high) (low)
        // duplicate values
        op(PUSHI(1)); // (1) (L-continue) (high) (low)
        op(DUPN); // (high) (L-continue) (high) (low)
        op(PUSHI(3)); // (3) (high) (L-continue) (high) (low)
        op(DUPN); // (low) (high) (L-continue) (high) (low)
        op(GT); // (high > low) (L-continue) (high) (low)
        // if high > low, skip end (goto continue)
        op(JMP); // (high) (low)
        // goto end
        goto("end"); // (high) (low)
      });
    
    // continued loop
    block("continue", () -> { // (high) (low)
        // calculate mid = (high + low) >> 1
        op(PUSHL("greater")); // (L-greater) (high) (low)
        op(PUSHI(2)); // (2) (L-greater) (high) (low)
        op(PUSHI(3)); // (3) (2) (L-greater) (high) (low)
        op(DUPN); // (low) (2) (L-greater) (high) (low)
        op(PUSHI(3)); // (3) (low) (2) (L-greater) (high) (low)
        op(DUPN); // (high) (low) (2) (L-greater) (high) (low)
        op(ADD); // (high + low) (2) (L-greater) (high) (low)
        op(DIV); // ((high + low) >> 1 -> mid) (L-greater) (high) (low)
        op(PUSHI(2)); // (2) (mid) (L-greater) (high) (low)
        op(PUSHI(1)); // (1) (2) (mid) (L-greater) (high) (low)
        op(DUPN); // (mid) (2) (mid) (L-greater) (high) (low)
        op(SWAP); // (mid) (L-greater) (mid) (high) (low)
        op(PUSHI(1)); // (1) (mid) (L-greater) (mid) (high) (low)
        op(ADD); // (mid + 1) (L-greater) (mid) (high) (low)
        
        // check against chef
        op(GTCHECK); // (mid + 1 > chef) (L-greater) (mid) (high) (low)
        
        // go to greater if (mid + 1 > chef)
        op(JMP); // (mid) (high) (low)
        
        // otherwise go to less
        goto("less"); // (mid) (high) (low)
      });
    
    // mid + 1 <= chef
    block("less", () -> { // (mid) (high) (low)
        // low = mid + 1
        op(PUSHI(1)); // (1) (mid) (high) (low)
        op(ADD); // (mid + 1) (high) (low)
        op(PUSHI(2)); // (2) (mid + 1) (high) (low)
        op(DROP); // (mid + 1) (high)
        op(PUSHI(1)); // (1) (mid + 1) (high)
        op(DUPN); // (high) (mid + 1 -> low) (high)
        op(PUSHI(2)); // (2) (high) (low) (high)
        op(DROP); // (high) (low)
        // loop
        goto("loop"); // (high) (low)
      });
    
    // mid + 1 > chef
    block("greater", () -> { // (mid) (high) (low)
        // high = mid
        op(PUSHI(1)); // (1) (mid) (high) (low)
        op(DROP); // (mid -> high) (low)
        // loop
        goto("loop"); // (high) (low)
      });
    
    // bsearch end
    block("end", () -> { // (high) (low)
        // drop high
        op(PUSHI(0)); // (0) (high) (low)
        op(DROP); // (low)
        // guess chef number
        op(CHECK); // -
        op(END);
        goto("bsearch");
      });
    
    // resolve labels
    code = code.map(block -> block.map(ins -> switch (ins) {
        case PUSHL(label):
        if (!labels.exists(label)) throw "no such label";
        PUSHI(labels[label]);
        case _: ins;
      }));
    
#if EMULATE
    emulate(code, stack);
#else
    assemble(code, stack);
#end
  }
  
  static function assemble(code:Array<Array<Ins>>, stack:Array<Int>):Void {
    var out = new haxe.io.BytesBuffer();
    function addString(s:String):Void {
      out.add(Bytes.ofString(s));
    }
    function addBytes(arr:Array<Int>):Void {
      var b = Bytes.alloc(arr.length);
      for (i in 0...arr.length) b.set(i, arr[i]);
      out.add(b);
    }
    addString('<meal>');
    for (block in code) {
      addString('\n  <course>');
      for (c in block) {
        switch (c) {
          case PUSHI(imm): addString('\n    <plate><paella>$imm</paella></plate>'); continue;
          case PUSHS(str): addString('\n    <plate><paella>$str</paella></plate>'); continue;
          case _:
        }
        addString('\n    <plate><');
        addBytes(switch (c) {
            case DBG: [0xE5, 0xAE, 0xAB, 0xE4, 0xBF, 0x9D, 0xE9, 0xB8, 0xA1, 0xE4, 0xB8, 0x81]; // '<宫保鸡丁/>';
            case DUPN: [0xEB, 0xB6, 0x88, 0xEA, 0xB3, 0xA0, 0xEA, 0xB8, 0xB0]; // '<불고기/>';
            case CHECK: [0xD0, 0x91, 0xD0, 0xBE, 0xD1, 0x80, 0xD1, 0x89]; // '<Борщ/>';
            case END: [0xE0, 0xA4, 0xA6, 0xE0, 0xA4, 0xBE, 0xE0, 0xA4, 0xB2]; // '<दाल/>';
            case GTCHECK: [0xE3, 0x83, 0xA9, 0xE3, 0x83, 0xBC, 0xE3, 0x83, 0xA1, 0xE3, 0x83, 0xB3]; // '<ラーメン/>';
            case GT: [0x73, 0x74, 0x72, 0x6F, 0x6F, 0x70, 0x77, 0x61, 0x66, 0x65, 0x6C, 0x73]; // '<stroopwafels/>';
            case SWAP: [0x6B, 0xC3, 0xB6, 0x74, 0x74, 0x62, 0x75, 0x6C, 0x6C, 0x61, 0x72]; // '<köttbullar/>';
            case DROP: [0xCE, 0xB3, 0xCF, 0x8D, 0xCF, 0x81, 0xCE, 0xBF, 0xCF, 0x82]; // '<γύρος/>';
            case ADD: [0x72, 0xC3, 0xB6, 0x73, 0x74, 0x69]; // '<rösti/>';
            case SUB: [0xD7, 0x9C, 0xD7, 0x90, 0xD6, 0xB7, 0xD7, 0x98, 0xD7, 0xA7, 0xD7, 0xA2, 0xD7, 0xA1]; // '<לאַטקעס/>';
            case MUL: [0x70, 0x6F, 0x75, 0x74, 0x69, 0x6E, 0x65]; // '<poutine/>';
            case DIV: [0xD8, 0xAD, 0xD9, 0x8F, 0xD9, 0x85, 0xD9, 0x8F, 0xD9, 0x91, 0xD8, 0xB5]; // '<حُمُّص/>';
            case JMP: [0xC3, 0xA6, 0x62, 0x6C, 0x65, 0x67, 0x72, 0xC3, 0xB8, 0x64]; // '<æblegrød/>';
            case _: [];
          });
        addString('/></plate>');
      }
      addString('\n  </course>');
    }
    addString('\n<state><drinks>');
    for (s in stack) {
      addString('\n  <value>$s</value>');
    }
    addString('\n</drinks></state></meal>');
    sys.io.File.saveBytes("sol.xml", out.getBytes());
  }
  
  static function emulate(code:Array<Array<Ins>>, stack:Array<Int>):Void {
    var chefNumbers = [ for (i in 0...5) Std.int(Math.random() * 0x7FFFFF) ];
    var cblock = code[0];
    var ip = 0;
    var cycleCount = 1;
    while (true) {
      if (cblock == null) { Sys.println("bad jump"); break; }
      if (cycleCount > 30000) { Sys.println("too many cycles"); break; }
      if (stack.length > 200) { Sys.println("stack too large"); break; }
      if (ip < 0 || ip >= cblock.length) { Sys.println("out of instructions"); break; }
      Sys.print('ins($ip): ${cblock[ip]}; ');
      switch (cblock[ip++]) {
        case DBG: Sys.println('chef: ${chefNumbers.join(",")}; stack: ${stack.join(",")}');
        case PUSHI(imm): stack.unshift(imm);
        //case PUSHS(s):
        //case PUSHL:
        //case LABEL:
        case DUPN: stack.unshift(stack[stack.shift()]);
        case CHECK:
        var chk = stack.shift();
        Sys.print('checking $chk against ${chefNumbers[0]} ... ');
        if (chefNumbers[0] == chk) { Sys.println("OK!"); chefNumbers.shift(); } else Sys.println("FAIL!");
        case END: if (chefNumbers.length == 0) { Sys.println("flag!"); break; }
        case GTCHECK: stack.unshift(stack.shift() > chefNumbers[0] ? 1 : 0);
        case GT: stack.unshift(stack.shift() < stack.shift() ? 1 : 0);
        case SWAP: var val = stack.shift(); var pos = stack.shift(); stack.insert(pos, val);
        case DROP: stack.splice(stack.shift(), 1);
        case ADD: stack.unshift(stack.shift() + stack.shift());
        case SUB: stack.unshift(stack.shift() - stack.shift());
        case MUL: stack.unshift(stack.shift() * stack.shift());
        case DIV: stack.unshift(Std.int(stack.shift() / stack.shift()));
        case JMP: var res = stack.shift(); var tgt = stack.shift(); if (res != 0) { cblock = code[tgt]; ip = 0; }
        case _: trace(cblock[ip - 1]); throw "?";
      }
      Sys.println('stack: ${stack.join(",")}'); // chef: ${chefNumbers.join(",")}
      cycleCount++;
    }
  }
}

enum Ins {
  /* x */ DBG; // debug - print chef drinks and own drinks (stack)
  /* x */ PUSHI(imm:Int); // push value to stack (immediate)
  /* x */ PUSHS(imm:String); // push value to stack (immediate)
  /* x */ PUSHL(label:String);
  /* x */ DUPN; // duplicate (top)th stack element
  /* . */ CHECK; // guess (chef-top) is (top)
  /* x */ END; // halt if all chef drinks guessed
  /* x */ GTCHECK; // push (top > chef-top)
  /* x */ GT; // push (2top > top)
  /* x */ SWAP; // move (top) to (2top) in stack
  /* x */ DROP; // remove (top) element
  /* x */ ADD; // push (top) + (2top)
  /* x */ SUB; // push (top) - (2top)
  /* x */ MUL; // push (top) * (2top)
  /* x */ DIV; // push integer divide (top) / (2top)
  /* . */ JMP; // go to (2top) if (top) != 0
}
