// haxe --run TakeL

import sys.net.*;

class TakeL {
  static function fill(n:Int, miss:Coord):Array<Tile> {
    if (n == 0) return [];
    if (n == 1) return [new Tile([
        for (y in 0...2) for (x in 0...2) {
          if (x == miss.x(n) && y == miss.y(n)) continue;
          Coord.xy(x, y, n);
        }
      ])];
    var missQ = miss.quarter(n);
    var halfSub = (1 << (n - 1)) - 1;
    var missCs = [ for (y in 0...2) for (x in 0...2) Coord.xy(x + halfSub, y + halfSub, n) ];
    // solve sub-board with mising square
    var ret = fill(n - 1, miss.compress(n, missQ)).map(t -> t.expand(n - 1, missQ));
    // add centre tile
    ret = ret.concat([new Tile([
        for (y in 0...2) for (x in 0...2) {
          var q:Quarter = x + y * 2;
          if (q == missQ) continue;
          missCs[(q:Int)];
        }
      ])]);
    // add missing quarters
    for (q in [TL, TR, BL, BR]) {
      if (q == missQ) continue;
      ret = ret.concat(fill(n - 1, missCs[(q:Int)].compress(n, q)).map(t -> t.expand(n - 1, q)));
    }
    return ret;
  }
  
  static function show(n:Int, ts:Array<Tile>):Void {
    var size = 1 << n;
    var grid = [ for (y in 0...size) [ for (x in 0...size) "." ] ];
    var alpha = "abcdefghijklmnopqrstuvwxyz".split("");
    var ap = 0;
    //Sys.println(ts);
    for (t in ts) {
      var tc = alpha[ap++];
      ap %= alpha.length;
      for (c in t.cs) {
        grid[c.y(n)][c.x(n)] = tc;
      }
    }
    Sys.println(grid.map(l -> l.join("")).join("\n") + "\n");
  }
  
  public static function main():Void {
    /*
    show(0, fill(0, Coord.xy(0, 0, 0)));
    show(1, fill(1, Coord.xy(0, 1, 1)));
    show(2, fill(2, Coord.xy(2, 3, 2)));
    show(3, fill(3, Coord.xy(2, 3, 3)));
    */
    
    var sock = new Socket();
    sock.connect(new Host("misc.chal.csaw.io"), 9000);
    
    // header
    for (i in 0...5) Sys.println(sock.input.readLine());
    
    // marked block
    var marked = {
      var markLine = sock.input.readLine();
      Sys.println(markLine);
      var c1 = markLine.substr(0, markLine.length - 1).split("(");
      var c2 = c1[1].split(", ");
      Coord.xy(Std.parseInt(c2[0]), Std.parseInt(c2[1]), 6);
    };
    
    // send solution
    var solution = fill(6, marked);
    for (t in solution) {
      sock.output.writeString(t.send(6) + "\n");
    }
    
    show(6, solution);
    
    for (i in 0...10) Sys.println(sock.input.readLine());
    
    /*
each L shaped block should be sent in its 
own line in a comma separated list
eg: (a,b),(a,c),(d,c)

grid dimensions 64x64
marked block: (64, 41)
    */
  }
}

@:enum
abstract Quarter(Int) from Int to Int {
  var TL = 0;
  var TR = 1;
  var BL = 2;
  var BR = 3;
}

abstract Coord(Int) from Int to Int {
  public static inline function xy(x:Int, y:Int, n:Int):Coord {
    return new Coord(x + y * (1 << n));
  }
  
  public inline function compress(n:Int, to:Quarter):Coord {
    var tx = x(n);
    var ty = y(n);
    var half = 1 << (n - 1);
    return xy(tx % half, ty % half, n - 1);
  }
  
  public inline function expand(n:Int, to:Quarter):Coord {
    var tx = x(n);
    var ty = y(n);
    var size = 1 << n;
    return xy(tx + ((to:Int) % 2 == 1 ? size : 0), ty + ((to:Int) >= 2 ? size : 0), n + 1);
  }
  
  public inline function x(n:Int):Int {
    return this % (1 << n);
  }
  
  public inline function y(n:Int):Int {
    return Std.int(this / (1 << n));
  }
  
  public inline function quarter(n:Int):Quarter {
    var tx = x(n);
    var ty = y(n);
    var half = 1 << (n - 1);
    return (tx >= half ? 1 : 0) + (ty >= half ? 2 : 0);
  }
  
  public inline function new(c:Int) {
    this = c;
  }
}

class Tile {
  public var cs:Array<Coord>;
  
  public function new(cs:Array<Coord>) {
    this.cs = cs;
  }
  
  public function expand(n:Int, to:Quarter):Tile {
    return new Tile(cs.map(c -> c.expand(n, to)));
  }
  
  public function send(n:Int):String {
    return cs.map(c -> '(${c.x(n)},${c.y(n)})').join(",");
  }
}
