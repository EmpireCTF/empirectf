import haxe.ds.Vector;

class SprintMap {
  public static function main():Void {
    var buf = new Vector<Int>(0x10000);
    for (i in 0...buf.length) buf[i] = 0;
    function r(pos:Int):Int {
      //if (pos >= buf.length - 1) throw 'r $pos';
      pos = pos & 0xFFFF;
      return buf[pos] + (buf[pos + 1] << 8);
    }
    function w(pos:Int, val:Int):Void {
      //if (pos >= buf.length - 1) throw 'r $pos';
      pos = pos & 0xFFFF;
      buf[pos] = val & 0xFF;
      buf[pos + 1] = (val >> 8) & 0xFF;
    }
    // raw
    {
      w(0x7000, 1);
      w(0x7002, 1);
      var map_position = 0x0002;
      do {
        if ((r(0x7000 + map_position * 2) & 0xFF) == 0) {
          var sub_position = (map_position * 2) & 0xFFFF;
          while (true) {
            w(0xFFEF, sub_position);
            if ((r(0xFFF0) & 0xFF) != 0) break;
            w(0x7000 + sub_position * 2, 0x0001);
            sub_position = (sub_position + map_position) & 0xFFFF;
          }
        }
        map_position = (map_position + 1) & 0xFFFF;
      } while ((map_position & 0xFF) != 0);
    };
    var map = haxe.io.Bytes.alloc(buf.length);
    for (i in 0...buf.length) map.set(i, buf[i]);
    sys.io.File.saveBytes("map-raw.bin", map);
    // remapping
    var remapped = haxe.io.Bytes.alloc(0x100);
    var sprintData = sys.io.File.getBytes("sprint-data.bin");
    for (i in 0...0x100) {
      var pos = sprintData.get(0xF000 + i);
      remapped.set(i, buf[0x7000 + pos * 2]);
    }
    sys.io.File.saveBytes("map-remapped.bin", remapped);
    // add checkpoints
    for (i in 0...9) {
      var pos = (-sprintData.get(0xF103 + i)) & 0xFF;
      remapped.set(pos, 0x10 + i);
    }
    sys.io.File.saveBytes("map-checkpoints.bin", remapped);
  }
}
