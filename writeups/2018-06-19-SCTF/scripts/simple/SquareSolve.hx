// haxe --run SquareSolve

class SquareSolve {
  public static function main():Void {
    function checkSquare(square:Array<Int>):Bool {
      var diag = 0;
      for (i in 0...5) {
        diag += square[i * 5 + i];
        diag += square[(4 - i) * 5 + i];
      }
      return diag >= 10;
    }
    function turnSquare(square:Array<Int>, turn:Int):Void {
      for (t in 0...turn) square.push(square.shift());
    }
    function solutionsFor(turn:Int):Array<Int> {
      var base = 0x315F00FF;
      return [ for (num in 49...112) {
          var input = base + (num << 8);
          var square = [ for (i in 0...5) for (j in 0...5)
              (input & (1 << (i * 5 + j))) >> (i * 5 + j)
            ];
          if (checkSquare(square)) turnSquare(square, turn);
          if (!checkSquare(square)) continue;
          num;
        } ];
    }
    Sys.println(
        [4, 8, 12]
          .map(solutionsFor)
          .map(sols -> sols.map(String.fromCharCode).join(""))
          .join("\n")
      );
  }
}
