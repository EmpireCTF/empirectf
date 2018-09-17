package hackit.secretkeeper.altair;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

public class Magix {
    public int cPtr;
    public int cccC;
    public int dPtr;
    public byte[] dtdtdta;
    public int lc;
    public String out;
    public InputStreamReader rC;
    public BufferedReader rF;

    public class Command {
        public static final char MAGIC1 = 'z';
        public static final char MAGIC2 = 'k';
        public static final char MAGIC3 = 'l';
        public static final char MAGIC4 = 'o';
        public static final char MAGIC5 = 'y';
        public static final char MAGIC6 = 'd';
        public static final char MAGIC7 = 'a';
        public static final char MAGIC8 = 'c';
    }

    public Magix(int i) {
        this(i, System.in);
    }

    public Magix(int i, InputStream inputStream) {
        this.dPtr = 0;
        this.cPtr = 0;
        this.lc = 0;
        this.cccC = 0;
        this.out = "";
        this.dPtr = 0;
        this.cPtr = 0;
        this.dtdtdta = new byte[i];
        this.rC = new InputStreamReader(inputStream);
    }

    public String doMagic(String str) throws Exception {
        while (this.cPtr < str.length()) {
            doMagic(str.charAt(this.cPtr), str.toCharArray());
            this.cPtr++;
        }
        this.dtdtdta = new byte[this.dtdtdta.length];
        this.dPtr = 0;
        this.cPtr = 0;
        return this.out;
    }

    protected void doMagic(char c, char[] cArr) throws Exception {
        int i;
        char c2;
        switch (c) {
            case 'a':
                if (this.dtdtdta[this.dPtr] == '\u0000') {
                    c = '\u0001';
                    while (c > '\u0000') {
                        i = this.cPtr + 1;
                        this.cPtr = i;
                        c2 = cArr[i];
                        if (c2 == Command.MAGIC7) {
                            c++;
                        } else if (c2 == Command.MAGIC8) {
                            c--;
                        }
                    }
                    break;
                }
                break;
            case 'c':
                c = '\u0001';
                while (c > '\u0000') {
                    i = this.cPtr - 1;
                    this.cPtr = i;
                    c2 = cArr[i];
                    if (c2 == Command.MAGIC7) {
                        c--;
                    } else if (c2 == Command.MAGIC8) {
                        c++;
                    }
                }
                this.cPtr--;
                break;
            case 'd':
                c = this.rC.read();
                if (c != -1) {
                    this.dtdtdta[this.dPtr] = (byte) c;
                    break;
                }
                return;
            case 'k':
                if (this.dPtr - '\u0001' >= '\u0000') {
                    this.dPtr--;
                    break;
                }
                throw new Exception("Bad Wolf");
            case 'l':
                if (this.dtdtdta[this.dPtr] + '\u0001' <= 2147483647) {
                    c = this.dtdtdta;
                    cArr = this.dPtr;
                    c[cArr] = (byte) (c[cArr] + 1);
                    break;
                }
                throw new Exception("Bad Wolf");
            case 'o':
                c = this.dtdtdta;
                cArr = this.dPtr;
                c[cArr] = (byte) (c[cArr] - 1);
                break;
            case 'y':
                c = new StringBuilder();
                c.append(this.out);
                c.append((char) this.dtdtdta[this.dPtr]);
                this.out = c.toString();
                break;
            case 'z':
                if (this.dPtr + '\u0001' <= this.dtdtdta.length) {
                    this.dPtr++;
                    break;
                }
                throw new Exception("Bad Wolf");
            default:
                break;
        }
        this.cccC++;
    }
}
