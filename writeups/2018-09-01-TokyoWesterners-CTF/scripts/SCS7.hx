// haxe --run SCS7

using StringTools;

class SCS7 {
  static var ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_".split("");
  // TWCTF{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}
  static var TARGET_LEN = 40;
  
  public static function main():Void {
    var matched:Array<String> = [];
    var possible:Array<String> = [""];
    
    function score(a:String, b:String):Int {
      for (match in 1...a.length) {
        if (a.substr(0, match) != b.substr(0, match)) {
          return match - 1;
        }
      }
      return a.length;
    }
    
    while (matched.length < TARGET_LEN) {
      var queries:Array<String> = [];
    
      var matching = 0;
      function makeFlag(chars:Array<String>):String {
        matching = chars.length;
        return "TWCTF{" + chars.slice(0, TARGET_LEN).join("").rpad(ALPHA[0], TARGET_LEN) + "}";
      }
    
      for (p in possible) {
        for (c1 in ALPHA) queries.push(makeFlag(matched.concat([p, c1])));
      }
    
      var bestLen = 0;
      var bestMatches = [];
    
      var files = 0;
      while (queries.length > 0) {
        files++;
        Sys.println('batch $files ...');
        var batch = queries.splice(0, 100);
        sys.io.File.saveContent("query.txt", batch.join("\n") + "\n");
        Sys.command('(cat query.txt; sleep 5) | nc crypto.chal.ctf.westerns.tokyo 14791 > response.txt');
      
        var resp = sys.io.File.getContent("response.txt").split("\n");
        var encFlag = resp[0].split(": ")[1];
        var qi = 0;
        for (q in batch) {
          var qResp = resp[qi + 2].split(": ")[2];
          var curLen = score(encFlag, qResp);
          if (curLen > bestLen) {
            bestLen = curLen;
            bestMatches = [q];
          } else if (curLen == bestLen) {
            bestMatches.push(q);
          }
          qi++;
        }
      }
      
      Sys.println('best matches ($bestLen):');
      Sys.println(bestMatches.join("\n"));
      
      if (bestMatches.length == 1) {
        matched = bestMatches[0].substr(6, matching - 1).split("");
        possible = [""];
        Sys.println('matched -> ${matched.join("")}');
      } else {
        var common = score(bestMatches[0], bestMatches[1]);
        Sys.println('common: $common');
        matched = bestMatches[0].substr(6, common - 6).split("");
        possible = [ for (m in bestMatches) m.substr(common, 1) ];
        Sys.println('matched  -> ${matched.join("")}');
        Sys.println('possible -> ${possible.join("")}');
      }
    }
  }
}
