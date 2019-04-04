// haxe --run Codes

class Codes {
  public static function main():Void {
    var matH = [
       [1, 0, 1, 0, 1, 0, 1]
      ,[0, 1, 1, 0, 0, 1, 1]
      ,[0, 0, 0, 1, 1, 1, 1]
    ];
    var matR = [
       [0, 0, 1, 0, 0, 0, 0]
      ,[0, 0, 0, 0, 1, 0, 0]
      ,[0, 0, 0, 0, 0, 1, 0]
      ,[0, 0, 0, 0, 0, 0, 1]
    ];
    function toBin(num:Int, len:Int):Array<Int> return [ for (i in 0...len) (num >> (len - 1 - i)) & 1 ];
    function matMul(mat:Array<Array<Int>>, vec:Array<Int>):Array<Int> {
      return [ for (row in 0...mat.length) {
          var parity = 0;
          for (i in 0...vec.length) parity += vec[i] * mat[row][i];
          parity & 1;
        } ];
    }
    var hammap = [ for (input in 0...128) toBin(input, 7).join("") => {
        var bits = toBin(input, 7);
        var syndrome = matMul(matH, bits);
        var err = (syndrome[0] << 0) | (syndrome[1] << 1) | (syndrome[2] << 2);
        if (err != 0) bits[err - 1] = 1 - bits[err - 1];
        matMul(matR, bits).join("");
      } ];
    var sock = new sys.net.Socket();
    sock.connect(new sys.net.Host("104.154.106.182"), 6969);
    function line():String {
      var ret = sock.input.readLine();
      Sys.println(ret);
      return ret;
    }
    // read intro
    for (i in 0...29) line();
    // solve prompts
    for (i in 0...100) {
      var prompt = line().split(" ")[2];
      if (!hammap.exists(prompt)) throw 'invalid prompt $prompt';
      sock.output.writeString(hammap[prompt] + "\n");
      sock.output.flush();
      line();
    }
    // read flag
    while (true) line();
/*
                        Welcome To 

     ____                       __    _______________  
    / __/__  __________ _____  / /_  / ___/_  __/ __/  
   / _// _ \/ __/ __/ // / _ \/ __/ / /__  / / / _/    
  /___/_//_/\__/_/  \_, / .__/\__/  \___/ /_/ /_/      
                ___/___/_/_____                        
               |_  |/ _ <  / _ \                       
              / __// // / /\_, /                       
             /____/\___/_//___/                        
                                                         

you will be receiving hamming(7,4) codes. your job is to send data bits
from a 7 bit hamming code. 
 ___________________________________________________________________
|                                                                   |
|   DO YOUR RESEARCH : https://en.wikipedia.org/wiki/Hamming(7,4)   |
|  FLAG WILL BE PRINTED AFTER YOU SEND CORRECT DATA BITS 100 TIMES  |
|___________________________________________________________________|

               the order of the bits followed is

                    P1 P2 D3 P4 D5 D6 D7


and come back here. remember somebits could be flipped. you need to send
correct data bits.

[*] CODE: 0001111
[*] DATA: 
*/
  }
}
