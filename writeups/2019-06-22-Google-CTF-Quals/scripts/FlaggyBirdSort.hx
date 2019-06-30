// haxe --run FlaggyBirdSort

class FlaggyBirdSort {
  public static function main():Void {
    // expected comparison results
    var ops = [0,0,0,0,1,0,0,1,0,1,1,1,1,0,0,0,1,1,0,0,1,0,1,0,0,0,1,1,1,0,0,0,1,0,0,0,0,1,1,1,1,1,0,1,0];
    
    // initial array, simply elements 0...15 in that order
    var input = [ for (i in 0...16) i ];
    
    while (true) {
      trace(input);
      try {
        // copy the array so we don't sort it
        var data = input.copy();
        var p = 0;
        
        function merge(pos:Int, len:Int):Void {
          if (len >= 2) {
            var half = len >> 1;
            merge(pos, half);
            merge(pos + half, half);
            var out = [];
            var idxA = pos;
            var idxB = pos + half;
            while (idxA < pos + half && idxB < pos + 2 * half) {
              if (data[idxA] >= data[idxB]) {
                if (data[idxA] <= data[idxB] || ops[p] == 1) {
                  throw [data[idxA], data[idxB]];
                }
                out.push(data[idxB++]);
              } else {
                if (ops[p] != 1) {
                  throw [data[idxA], data[idxB]];
                }
                out.push(data[idxA++]);
              }
              p++;
            }
            while (idxA < pos + half) out.push(data[idxA++]);
            while (idxB < pos + 2 * half) out.push(data[idxB++]);
            for (i in 0...len) data[i + pos] = out[i];
          }
        }
        merge(0, 16);
        
        // no failures - finish
        break;
      } catch (e:Dynamic) {
        var i = input.indexOf(e[0]);
        var j = input.indexOf(e[1]);
        
        // swap the indices i and j in the input array
        var t = input[i];
        input[i] = input[j];
        input[j] = t;
      }
    }
  }
}
