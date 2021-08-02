// haxe --run Parking

using Lambda;

class Parking {
  public static function main():Void {
    var script = new StringBuf();
    var add = script.add;

    add("(declare-const flag (_ BitVec 64))\n");

    add("(declare-const u1a (_ BitVec 64))\n");
    add("(declare-const u1b (_ BitVec 64))\n");

    add("(declare-const u2a (_ BitVec 64))\n");
    add("(declare-const u2b (_ BitVec 64))\n");
    add("(declare-const u2c (_ BitVec 64))\n");
    add("(declare-const u2d (_ BitVec 64))\n");

    add("(declare-const lu3a (_ BitVec 64))\n");
    add("(declare-const lu3b (_ BitVec 64))\n");
    add("(declare-const u3a (_ BitVec 64))\n");
    add("(declare-const u3b (_ BitVec 64))\n");
    add("(declare-const u3c (_ BitVec 64))\n");
    add("(declare-const u3d (_ BitVec 64))\n");

    add("(declare-const u4a (_ BitVec 64))\n");
    add("(declare-const u4b (_ BitVec 64))\n");

    add("(declare-const u5a (_ BitVec 64))\n");
    add("(declare-const u5b (_ BitVec 64))\n");
    add("(declare-const u5c (_ BitVec 64))\n");
    add("(declare-const u5d (_ BitVec 64))\n");

    add("(declare-const lu6a (_ BitVec 64))\n");
    add("(declare-const lu6b (_ BitVec 64))\n");
    add("(declare-const u6a (_ BitVec 64))\n");
    add("(declare-const u6b (_ BitVec 64))\n");
    add("(declare-const u6c (_ BitVec 64))\n");
    add("(declare-const u6d (_ BitVec 64))\n");

    add("(declare-const u7a (_ BitVec 64))\n");
    add("(declare-const u7b (_ BitVec 64))\n");

    add("(declare-const bs1 (_ BitVec 64))\n");
    add("(declare-const bs2 (_ BitVec 64))\n");
    add("(declare-const bs3 (_ BitVec 64))\n");
    add("(assert (= bs1 #b1101111010101101110000001101111011011110101011011100000011011110))\n");
    add("(assert (= bs2 #b0001001100110111000100110011011100010011001101110001001100110111))\n");
    add("(assert (= bs3 #b0001111100010101101000010101010110101000101100111000010000001010))\n");

    function unit(res:String, a:String, b:String, c:String, d:String, full:Bool):Void {
      add('(assert (= ${res}a (bvor (bvand $a $c) (bvand $b $d))))\n');
      add('(assert (= ${res}b (bvor (bvand $a $d) (bvand $b $c))))\n');
      if (full) {
        add('(assert (= ${res}c (bvor (bvor (bvand $a $c) (bvand $a $d)) (bvand $b $c))))\n');
        add('(assert (= ${res}d (bvand $b $d)))\n');
      }
    }

    unit("u1", "(bvnot flag)", "flag", "(bvnot bs1)", "bs1", false);
    unit("u2", "(bvor (bvshl u1a #x0000000000000001) #x0000000000000001)", "(bvshl u1b #x0000000000000001)", "u1a", "u1b", true);
    add('(assert (= lu3a (bvand u2c u3c)))\n');
    add('(assert (= lu3b (bvor u2d u3d)))\n');
    unit("u3", "u2a", "u2b", "(bvor (bvshl lu3a #x0000000000000001) #x0000000000000001)", "(bvshl lu3b #x0000000000000001)", true);
    unit("u4", "u3a", "u3b", "(bvor (bvlshr u3a #x0000000000000001) #x8000000000000000)", "(bvlshr u3b #x0000000000000001)", false);
    unit("u5", "((_ rotate_right 1) u4a)", "((_ rotate_right 1) u4b)", "(bvnot bs2)", "bs2", true);
    add('(assert (= lu6a (bvand u5c u6c)))\n');
    add('(assert (= lu6b (bvor u5d u6d)))\n');
    unit("u6", "u5a", "u5b", "(bvor (bvshl lu6a #x0000000000000001) #x0000000000000001)", "(bvshl lu6b #x0000000000000001)", true);
    unit("u7", "(bvnot bs3)", "bs3", "u6a", "u6b", false);

    add('(assert (= u7a #xffffffffffffffff))\n');

    add("(check-sat)\n");
    add("(get-model)\n");

    sys.io.File.saveContent("parking.z3", script.toString());
  }
}
