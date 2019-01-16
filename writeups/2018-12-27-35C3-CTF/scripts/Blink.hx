// run with blink.csv in the CWD:
// haxe --run Blink

class Blink {
  public static function main():Void {
    var f = sys.io.File.read("blink.csv");
    
    // skip metadata
    for (i in 0...21) f.readLine();
    
    // parsing
    var entryCount = 0;
    var clockCount = 0;
    var currentEntry:Entry = null;
    function nextEntry():Null<Entry> {
      entryCount++;
      return currentEntry = (try f.readLine().split(",").slice(1).map(Std.parseInt)
        catch (e:Dynamic) null);
    }
    function readUntil(f:Entry->Bool):Void {
      while (true) {
        nextEntry();
        if (currentEntry == null) break;
        if (f(currentEntry)) break;
      }
    }
    function nextClockCycle(f:Void->Void):Void {
      readUntil(e -> e.clk == 0); // read until clock goes high
      f();
      clockCount++; readUntil(e -> e.clk == 1); // prepare for next cycle
    }
    
    // colours
    function rgb(r:Int, g:Int, b:Int):String {
      var col = 16 + 36 * r + 6 * g + b;
      return '\x1B[48;5;${col}m';
    }
    function entryRGB(e:Entry):String {
      return rgb(e.r1 * 2 + e.r2, e.g1 * 2 + e.g2, e.b1 * 2 + e.b2);
    }
    
    // 128x64 pixels?
    for (y in 0...64) {
      for (x in 0...128) {
        nextClockCycle(() -> Sys.print('${entryRGB(currentEntry)} '));
      }
      Sys.println("");
    }
  }
}

abstract Entry(Array<Int>) from Array<Int> {
  public inline function new(a:Array<Int>) this = a;
  
  // Label,OE,LAT,CLK,E,D,C,B,A,B2,B1,G2,G1,R2,R1
  // TIME,D13,D12,D11,D10,D9,D8,D7,D6,D5,D4,D3,D2,D1,D0
  
  public var oe(get, never):Int;
  private inline function get_oe():Int return this[0];
  public var lat(get, never):Int;
  private inline function get_lat():Int return this[1];
  public var clk(get, never):Int;
  private inline function get_clk():Int return this[2];
  public var e(get, never):Int;
  private inline function get_e():Int return this[3];
  public var d(get, never):Int;
  private inline function get_d():Int return this[4];
  public var c(get, never):Int;
  private inline function get_c():Int return this[5];
  public var b(get, never):Int;
  private inline function get_b():Int return this[6];
  public var a(get, never):Int;
  private inline function get_a():Int return this[7];
  public var b2(get, never):Int;
  private inline function get_b2():Int return this[8];
  public var b1(get, never):Int;
  private inline function get_b1():Int return this[9];
  public var g2(get, never):Int;
  private inline function get_g2():Int return this[10];
  public var g1(get, never):Int;
  private inline function get_g1():Int return this[11];
  public var r2(get, never):Int;
  private inline function get_r2():Int return this[12];
  public var r1(get, never):Int;
  private inline function get_r1():Int return this[13];
}
