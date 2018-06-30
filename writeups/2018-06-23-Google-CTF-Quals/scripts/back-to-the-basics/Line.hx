import haxe.io.Bytes;

using StringTools;

class Line {
  static var TOKENS = [
      128 => "END",
      129 => "FOR",
      130 => "NEXT",
      131 => "DATA",
      132 => "INPUT#",
      133 => "INPUT",
      134 => "DIM",
      135 => "READ",
      136 => "LET",
      137 => "GOTO",
      138 => "RUN",
      139 => "IF",
      140 => "RESTORE",
      141 => "GOSUB",
      142 => "RETURN",
      143 => "REM",
      144 => "STOP",
      145 => "ON",
      146 => "WAIT",
      147 => "LOAD",
      148 => "SAVE",
      149 => "VERIFY",
      150 => "DEF",
      151 => "POKE",
      152 => "PRINT#",
      153 => "PRINT",
      154 => "CONT",
      155 => "LIST",
      156 => "CLR",
      157 => "CMD",
      158 => "SYS",
      159 => "OPEN",
      160 => "CLOSE",
      161 => "GET",
      162 => "NEW",
      163 => "TAB(",
      164 => "TO",
      165 => "FN",
      166 => "SPC(",
      167 => "THEN",
      168 => "NOT",
      169 => "STEP",
      170 => "+",
      171 => "-",
      172 => "*",
      173 => "/",
      174 => "^",
      175 => "AND",
      176 => "OR",
      177 => ">",
      178 => "=",
      179 => "<",
      180 => "SGN",
      181 => "INT",
      182 => "ABS",
      183 => "USR",
      184 => "FRE",
      185 => "POS",
      186 => "SQR",
      187 => "RND",
      188 => "LOG",
      189 => "EXP",
      190 => "COS",
      191 => "SIN",
      192 => "TAN",
      193 => "ATN",
      194 => "PEEK",
      195 => "LEN",
      196 => "STR$",
      197 => "VAL",
      198 => "ASC",
      199 => "CHR$",
      200 => "LEFT$",
      201 => "RIGHT$",
      202 => "MID$",
      203 => "GO",
    ];
  
  public static function fromMemory(m:Bytes, addr:Int):Line {
    var ret = new Line();
    ret.address = addr;
    ret.nextAddress = m.get(addr) | (m.get(addr + 1) << 8);
    ret.number = m.get(addr + 2) | (m.get(addr + 3) << 8);
    var end = addr + 4;
    while (end < m.length && m.get(end) != 0) end++;
    ret.data = m.getString(addr + 4, end - (addr + 4));
    return ret;
  }
  
  public var address:Int;
  public var nextAddress:Int;
  public var number:Int;
  public var data:String;
  
  public var end(get, never):Bool;
  private inline function get_end():Bool {
    return nextAddress == 0 && number == 0;
  }
  
  public var binary(get, never):Bool;
  private inline function get_binary():Bool {
    return data.length > 100;
  }
  
  public function new() {}
  
  public function detokenise():String {
    var ret = new StringBuf();
    for (i in 0...data.length) {
      var cc = data.charCodeAt(i);
      if (TOKENS.exists(cc)) ret.add(TOKENS[cc]);
      else if (cc >= 0x20 && cc <= 0x7F) ret.addChar(cc);
      else ret.addChar("%".code);
    }
    return ret.toString();
  }
  
  public function toString():String {
    if (binary) return '${address.hex(4)}: -----: <BINARY>';
    return '${address.hex(4)}: ${Std.string(number).lpad(" ", 5)}: ' + detokenise();
  }
}
