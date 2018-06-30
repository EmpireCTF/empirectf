class Wire {
  var tsIdx:Int;
  var dataIdx:Int;
  var f:sys.io.FileInput;
  var curValue:Int;
  var nextValue:Int = -1;
  public var nextTS:Float;
  
  public function new(tsIdx:Int, dataIdx:Int) {
    this.tsIdx = tsIdx;
    this.dataIdx = dataIdx;
    f = sys.io.File.read("data.csv");
    f.readLine();
    parse();
  }
  
  function parse():Void {
    curValue = nextValue;
    var line = f.readLine().split(",");
    nextValue = Std.parseInt(line[dataIdx]);
    nextTS = Std.parseFloat(line[tsIdx]);
  }
  
  public function at(ts:Float):Int {
    if (ts >= nextTS) parse();
    return curValue;
  }
}
