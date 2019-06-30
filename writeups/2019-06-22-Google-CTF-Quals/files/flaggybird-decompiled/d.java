package com.google.ctf.game;

import com.badlogic.gdx.graphics.g2d.b;
import java.util.ArrayList;
import java.util.List;

class d {
    boolean a;
    int b;
    private int c;
    private int d;
    private int e;
    private List<com.badlogic.gdx.graphics.g2d.d> f;

    d(com.badlogic.gdx.graphics.g2d.d dVar, int i, int i2, int i3) {
        this.f = new ArrayList();
        this.f.add(dVar);
        this.c = i;
        this.d = i2;
        this.e = i3;
        this.a = false;
    }

    d(List<com.badlogic.gdx.graphics.g2d.d> list, int i, int i2, int i3, int i4) {
        this.f = list;
        this.c = i;
        this.d = i2;
        this.e = i3;
        this.a = false;
        this.b = i4;
    }

    /* Access modifiers changed, original: 0000 */
    public void a(int i, int i2) {
        if (i >= this.c && i <= this.c + this.e && i2 >= this.d && i2 <= this.d + this.e) {
            this.a = true;
        }
    }

    /* Access modifiers changed, original: 0000 */
    public void a(b bVar) {
        for (com.badlogic.gdx.graphics.g2d.d a : this.f) {
            bVar.a(a, (float) this.c, (float) this.d);
        }
    }
}
