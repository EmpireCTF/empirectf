package com.google.ctf.game;

import com.badlogic.gdx.g;
import com.badlogic.gdx.graphics.g2d.b;
import com.badlogic.gdx.graphics.g2d.d;
import com.badlogic.gdx.graphics.l;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.InflaterInputStream;

class f {
    static final a[] a = new a[]{a.EGG_0, a.EGG_1, a.EGG_2, a.EGG_3, a.EGG_4, a.EGG_5, a.EGG_6, a.EGG_7, a.EGG_8, a.EGG_9, a.EGG_10, a.EGG_11, a.EGG_12, a.EGG_13, a.EGG_14, a.EGG_15};
    static final a[] b = new a[]{a.FLAG_0, a.FLAG_1, a.FLAG_2, a.FLAG_3, a.FLAG_4, a.FLAG_5, a.FLAG_6, a.FLAG_7, a.FLAG_8, a.FLAG_9, a.FLAG_10, a.FLAG_11, a.FLAG_12, a.FLAG_13, a.FLAG_14, a.FLAG_15};
    a[][] c;
    int[][] d;
    int e;
    int f;
    h g;
    private int h = 190;
    private int i = 46;
    private d[][] j;
    private int[][] k;
    private a[] l;
    private List<Integer> m;
    private int n;
    private int o;

    enum a {
        AIR,
        GROUND,
        DIAGONAL_A,
        DIAGONAL_AA,
        DIAGONAL_B,
        DIAGONAL_C,
        DIAGONAL_CC,
        DIAGONAL_D,
        DIAGONAL_DD,
        DIAGONAL_E,
        DIAGONAL_F,
        DIAGONAL_FF,
        DIAGONAL_G,
        DIAGONAL_GG,
        DIAGONAL_H,
        DIAGONAL_I,
        DIAGONAL_II,
        DIAGONAL_J,
        DIAGONAL_JJ,
        DIAGONAL_K,
        DIAGONAL_L,
        DIAGONAL_LL,
        COMPUTER,
        EGG_HOLDER,
        EGG_0,
        EGG_1,
        EGG_2,
        EGG_3,
        EGG_4,
        EGG_5,
        EGG_6,
        EGG_7,
        EGG_8,
        EGG_9,
        EGG_10,
        EGG_11,
        EGG_12,
        EGG_13,
        EGG_14,
        EGG_15,
        BACKGROUND,
        PORTAL,
        FLAG_0,
        FLAG_1,
        FLAG_2,
        FLAG_3,
        FLAG_4,
        FLAG_5,
        FLAG_6,
        FLAG_7,
        FLAG_8,
        FLAG_9,
        FLAG_10,
        FLAG_11,
        FLAG_12,
        FLAG_13,
        FLAG_14,
        FLAG_15
    }

    f(h hVar) {
        this.g = hVar;
        l lVar = new l(g.e.a("tileset.png"));
        this.e = lVar.a() / 16;
        this.f = lVar.b() / 8;
        this.j = d.a(lVar, this.e, this.f);
        this.n = 0;
        this.o = 1;
        a(this.o);
    }

    private a a(byte b) {
        if (b == (byte) 65) {
            return a.DIAGONAL_AA;
        }
        if (b == (byte) 120) {
            return a.BACKGROUND;
        }
        switch (b) {
            case (byte) 49:
                return a.GROUND;
            case (byte) 50:
                return a.EGG_HOLDER;
            case (byte) 51:
                return a.COMPUTER;
            case (byte) 52:
                return a.PORTAL;
            default:
                switch (b) {
                    case (byte) 67:
                        return a.DIAGONAL_CC;
                    case (byte) 68:
                        return a.DIAGONAL_DD;
                    default:
                        switch (b) {
                            case (byte) 70:
                                return a.DIAGONAL_FF;
                            case (byte) 71:
                                return a.DIAGONAL_GG;
                            default:
                                switch (b) {
                                    case (byte) 73:
                                        return a.DIAGONAL_II;
                                    case (byte) 74:
                                        return a.DIAGONAL_JJ;
                                    default:
                                        switch (b) {
                                            case (byte) 76:
                                                return a.DIAGONAL_LL;
                                            case (byte) 77:
                                                return a.FLAG_1;
                                            case (byte) 78:
                                                return a.FLAG_3;
                                            case (byte) 79:
                                                return a.FLAG_5;
                                            case (byte) 80:
                                                return a.FLAG_7;
                                            case (byte) 81:
                                                return a.FLAG_9;
                                            case (byte) 82:
                                                return a.FLAG_11;
                                            case (byte) 83:
                                                return a.FLAG_13;
                                            case (byte) 84:
                                                return a.FLAG_15;
                                            default:
                                                switch (b) {
                                                    case (byte) 97:
                                                        return a.DIAGONAL_A;
                                                    case (byte) 98:
                                                        return a.DIAGONAL_B;
                                                    case (byte) 99:
                                                        return a.DIAGONAL_C;
                                                    case (byte) 100:
                                                        return a.DIAGONAL_D;
                                                    case (byte) 101:
                                                        return a.DIAGONAL_E;
                                                    case (byte) 102:
                                                        return a.DIAGONAL_F;
                                                    case (byte) 103:
                                                        return a.DIAGONAL_G;
                                                    case (byte) 104:
                                                        return a.DIAGONAL_H;
                                                    case (byte) 105:
                                                        return a.DIAGONAL_I;
                                                    case (byte) 106:
                                                        return a.DIAGONAL_J;
                                                    case (byte) 107:
                                                        return a.DIAGONAL_K;
                                                    case (byte) 108:
                                                        return a.DIAGONAL_L;
                                                    case (byte) 109:
                                                        return a.FLAG_0;
                                                    case (byte) 110:
                                                        return a.FLAG_2;
                                                    case (byte) 111:
                                                        return a.FLAG_4;
                                                    case (byte) 112:
                                                        return a.FLAG_6;
                                                    case (byte) 113:
                                                        return a.FLAG_8;
                                                    case (byte) 114:
                                                        return a.FLAG_10;
                                                    case (byte) 115:
                                                        return a.FLAG_12;
                                                    case (byte) 116:
                                                        return a.FLAG_14;
                                                    default:
                                                        return a.AIR;
                                                }
                                        }
                                }
                        }
                }
        }
    }

    private void a(int i) {
        a(g.e.a(String.format("level%d.bin", new Object[]{Integer.valueOf(i)})).i());
    }

    private void a(byte[] bArr) {
        InflaterInputStream inflaterInputStream = new InflaterInputStream(new ByteArrayInputStream(bArr));
        byte[] bArr2 = new byte[(this.h * this.i)];
        if (inflaterInputStream.read(bArr2) == this.h * this.i) {
            int i;
            int i2;
            this.c = new a[this.i][];
            this.d = new int[this.i][];
            this.k = new int[32][];
            int i3 = 0;
            for (i = 0; i < this.i; i++) {
                this.c[i] = new a[this.h];
                this.d[i] = new int[this.h];
                for (i2 = 0; i2 < this.h; i2++) {
                    this.d[i][i2] = -1;
                }
            }
            this.n = 0;
            for (i = 0; i < this.i; i++) {
                for (i2 = 0; i2 < this.h; i2++) {
                    a a = a(bArr2[(this.h * i) + i2]);
                    this.c[(this.i - i) - 1][i2] = a;
                    if (a == a.EGG_HOLDER) {
                        this.d[(this.i - i) - 1][i2] = this.n;
                        this.k[this.n] = new int[]{i2, (this.i - i) - 1};
                        this.n++;
                    }
                }
            }
            this.l = new a[this.n];
            while (i3 < this.l.length) {
                this.l[i3] = a.EGG_0;
                i3++;
            }
            this.m = new ArrayList();
            return;
        }
        throw new IOException();
    }

    /* Access modifiers changed, original: 0000 */
    public d a(a aVar) {
        switch (aVar) {
            case AIR:
                return null;
            case COMPUTER:
                return this.j[5][1];
            case EGG_HOLDER:
                return this.j[4][1];
            case BACKGROUND:
                return this.j[7][1];
            case PORTAL:
                return this.j[3][1];
            case DIAGONAL_A:
                return this.j[0][4];
            case DIAGONAL_AA:
                return this.j[0][5];
            case DIAGONAL_B:
                return this.j[1][6];
            case DIAGONAL_C:
                return this.j[2][7];
            case DIAGONAL_CC:
                return this.j[3][7];
            case DIAGONAL_D:
                return this.j[4][7];
            case DIAGONAL_DD:
                return this.j[5][7];
            case DIAGONAL_E:
                return this.j[6][6];
            case DIAGONAL_F:
                return this.j[7][5];
            case DIAGONAL_FF:
                return this.j[7][4];
            case DIAGONAL_G:
                return this.j[7][3];
            case DIAGONAL_GG:
                return this.j[7][2];
            case DIAGONAL_H:
                return this.j[6][1];
            case DIAGONAL_I:
                return this.j[5][0];
            case DIAGONAL_II:
                return this.j[4][0];
            case DIAGONAL_J:
                return this.j[3][0];
            case DIAGONAL_JJ:
                return this.j[2][0];
            case DIAGONAL_K:
                return this.j[1][1];
            case DIAGONAL_L:
                return this.j[0][2];
            case DIAGONAL_LL:
                return this.j[0][3];
            case EGG_0:
                return this.j[2][2];
            case EGG_1:
                return this.j[2][3];
            case EGG_2:
                return this.j[2][4];
            case EGG_3:
                return this.j[2][5];
            case EGG_4:
                return this.j[3][2];
            case EGG_5:
                return this.j[3][3];
            case EGG_6:
                return this.j[3][4];
            case EGG_7:
                return this.j[3][5];
            case EGG_8:
                return this.j[4][2];
            case EGG_9:
                return this.j[4][3];
            case EGG_10:
                return this.j[4][4];
            case EGG_11:
                return this.j[4][5];
            case EGG_12:
                return this.j[5][2];
            case EGG_13:
                return this.j[5][3];
            case EGG_14:
                return this.j[5][4];
            case EGG_15:
                return this.j[5][5];
            case FLAG_0:
                return this.j[4][8];
            case FLAG_1:
                return this.j[4][9];
            case FLAG_2:
                return this.j[4][10];
            case FLAG_3:
                return this.j[4][11];
            case FLAG_4:
                return this.j[5][8];
            case FLAG_5:
                return this.j[5][9];
            case FLAG_6:
                return this.j[5][10];
            case FLAG_7:
                return this.j[5][11];
            case FLAG_8:
                return this.j[6][8];
            case FLAG_9:
                return this.j[6][9];
            case FLAG_10:
                return this.j[6][10];
            case FLAG_11:
                return this.j[6][11];
            case FLAG_12:
                return this.j[7][8];
            case FLAG_13:
                return this.j[7][9];
            case FLAG_14:
                return this.j[7][10];
            case FLAG_15:
                return this.j[7][11];
            default:
                return this.j[0][0];
        }
    }

    /* Access modifiers changed, original: 0000 */
    public void a() {
        byte[] bArr = new byte[32];
        for (int i = 0; i < this.l.length; i++) {
            for (int i2 = 0; i2 < a.length; i2++) {
                if (this.l[i] == a[i2]) {
                    bArr[i] = (byte) i2;
                }
            }
        }
        bArr = new Checker().a(bArr);
        if (bArr != null) {
            try {
                this.o = 0;
                a(bArr);
                return;
            } catch (IOException unused) {
                return;
            }
        }
        this.g.a("Close, but no cigar.");
    }

    /* Access modifiers changed, original: 0000 */
    public void a(int i, int i2) {
        this.l[i] = a[i2];
        int i3 = -1;
        for (int i4 = 0; i4 < this.m.size(); i4++) {
            if (((Integer) this.m.get(i4)).intValue() == i) {
                if (i2 == 0) {
                    i3 = i4;
                } else {
                    return;
                }
            }
        }
        if (i3 != -1) {
            this.m.remove(i3);
        }
        if (i2 != 0) {
            this.m.add(Integer.valueOf(i));
            if (this.m.size() > 15) {
                this.l[((Integer) this.m.remove(0)).intValue()] = a.EGG_0;
            }
        }
    }

    /* Access modifiers changed, original: 0000 */
    public void a(b bVar, c cVar) {
        int i = ((int) cVar.a.d) / this.e;
        int i2 = ((int) cVar.a.e) / this.f;
        for (int max = Math.max(i2 - 12, 0); max < Math.min(i2 + 12, this.i); max++) {
            for (int max2 = Math.max(i - 16, 0); max2 < Math.min(i + 16, this.h); max2++) {
                d a = a(this.c[max][max2]);
                if (a != null) {
                    float round = ((float) Math.round(((float) (max2 * 128)) * 10.0f)) / 10.0f;
                    float round2 = ((float) Math.round(((float) (max * 128)) * 10.0f)) / 10.0f;
                    if (this.d[max][max2] != -1) {
                        d a2 = a(this.l[this.d[max][max2]]);
                        if (a2 != null) {
                            bVar.a(a2, round, round2);
                        }
                    }
                    bVar.a(a, round, round2);
                }
            }
        }
    }

    /* Access modifiers changed, original: 0000 */
    public void a(b bVar) {
        this.o++;
        try {
            a(this.o);
        } catch (IOException unused) {
        }
        bVar.a.d = 1408.0f;
        bVar.a.e = 2560.0f;
    }
}
