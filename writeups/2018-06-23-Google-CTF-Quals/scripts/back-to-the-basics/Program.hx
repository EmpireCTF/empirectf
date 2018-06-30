import haxe.io.Bytes;
import sys.io.File;

class Program {
  public static function load(path:String):{memory:Bytes, loadAt:Int, loaded:Int} {
    var memory = Bytes.alloc(65536);
    var data = File.getBytes("crackme.prg");
    var loadAt = data.get(0) | (data.get(1) << 8);
    memory.blit(loadAt, data, 2, data.length - 2);
    return {memory: memory, loadAt: loadAt, loaded: data.length};
  }
}
