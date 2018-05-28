// compile with haxe -main TNT -neko tnt.n
// run with neko tnt.n
// assuming an ex.csv file in cwd

using StringTools;

class TNT {
  public static function main():Void {
    var data = sys.io.File.getContent("ex.csv")
      .split("\n")
      .map(l -> l.substr(1, l.length - 2).split('","'))
      .filter(l -> l[4] == "HTTP");
    var lastTime = 0.0;
    var lastReq = "";
    var lastInj = false;
    /*
    GET /vulnerabilities/sqli_blind/?id=2%27%20AND%209666%3DIF%28%28ORD%28MID%28%28SELECT%20IFNULL%28CAST%28COUNT%28DISTINCT%28schema_name%29%29%20AS%20CHAR%29%2C0x20%29%20FROM%20INFORMATION_SCHEMA.SCHEMATA%29%2C1%2C1%29%29%3E259853%29%2CSLEEP%285%29%2C9666%29%20AND%20%27fQys%27%3D%27fQys&Submit=Submit HTTP/1.1 
    2' AND 2301=IF((ORD(MID((SELECT IFNULL(CAST(comment AS CHAR),0x20) FROM dvwa.guestbook ORDER BY name LIMIT 0,1),1,1))>250507),SLEEP(1),2301) AND 'sXCb'='sXCb,false
    */
    var cols = new Map<String, Array<Array<Int>>>();
    inline function max(a, b) return (a > b ? a : b);
    inline function min(a, b) return (a < b ? a : b);
    var pi = Std.parseInt;
    for (e in data) {
      if (e[2] == "192.168.154.156") { // request
        var isInj = (e[6].startsWith("GET /vulnerabilities/sqli_blind/?id="));
        lastInj = isInj;
        if (!isInj) continue;
        var id = e[6].substr("GET /vulnerabilities/sqli_blind/?id=".length);
        id = id.substr(0, id.length - "&Submit=Submit HTTP/1.1 ".length);
        lastReq = id.urlDecode();
        lastTime = Std.parseFloat(e[1]);
      } else if (lastInj) { // response
        var curTime = Std.parseFloat(e[1]);
        var res = (curTime - lastTime) > .5;
        if (lastReq.substr(12, 32) == "IF((ORD(MID((SELECT IFNULL(CAST(") {
          lastReq = lastReq.substr(44);
          var comma = lastReq.indexOf(" ");
          var column = lastReq.substr(0, comma);
          if (column.startsWith("COUNT(")) continue;
          if (!cols.exists(column)) cols.set(column, []);
          lastReq = lastReq.substr(lastReq.indexOf("LIMIT 0,1),") + 11);
          comma = lastReq.indexOf(",");
          var cpos = pi(lastReq.substr(0, comma));
          if (cpos == null) continue;
          lastReq = lastReq.substr(comma);
          lastReq = lastReq.substr(4);
          comma = lastReq.indexOf(")");
          var test = lastReq.substr(0, comma);
          if (test.length <= 5) {
            while (cpos >= cols[column].length) cols[column].push([0, 255]);
            if (cols[column][cpos][0] == cols[column][cpos][1]) continue;
            function handleTest(t:String, res:Bool):Void {
              switch [t, res] {
                case [_.startsWith(">=") => true, false]: handleTest("<"  + t.substr(2), true);
                case [_.startsWith("<=") => true, false]: handleTest(">"  + t.substr(2), true); 
                case [_.startsWith(">")  => true, false]: handleTest("<=" + t.substr(1), true); 
                case [_.startsWith("<")  => true, false]: handleTest(">=" + t.substr(1), true); 
                case [_.startsWith("!=") => true, false]: handleTest("==" + t.substr(2), true); 
                case [_.startsWith("==") => true, false]: handleTest("!=" + t.substr(2), true); 
                case [_.startsWith(">=") => true, true]: cols[column][cpos][0] = max(cols[column][cpos][0], pi(t.substr(2)));
                case [_.startsWith("<=") => true, true]: cols[column][cpos][1] = min(cols[column][cpos][1], pi(t.substr(2)));
                case [_.startsWith(">")  => true, true]: cols[column][cpos][0] = max(cols[column][cpos][0], pi(t.substr(1)) + 1);
                case [_.startsWith("<")  => true, true]: cols[column][cpos][1] = min(cols[column][cpos][1], pi(t.substr(1)) - 1);
                case [_.startsWith("!=") => true, true]:
                if (cols[column][cpos][0] == pi(t.substr(2))) cols[column][cpos][0]++;
                if (cols[column][cpos][1] == pi(t.substr(2))) cols[column][cpos][1]--; 
                case [_.startsWith("==") => true, true]: cols[column][cpos] = [pi(t.substr(2)), pi(t.substr(2))];
                case _:
                trace('unknown test! $test');
                Sys.exit(1);
              }
            }
            handleTest(test, res);
          }
        }
      }
    }
    for (c in cols.keys()) {
      Sys.println(c);
      var data = cols[c];
      var out = new StringBuf();
      for (i in 1...data.length - 1) {
        if (data[i][0] != data[i][1]) out.add("?");
        else out.addChar(data[i][0]);
      }
      Sys.println(out.toString());
    }
  }
}
