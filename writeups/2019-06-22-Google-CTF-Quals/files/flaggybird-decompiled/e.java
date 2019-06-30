package com.google.ctf.game;

import com.badlogic.gdx.b;
import com.badlogic.gdx.g;
import com.badlogic.gdx.graphics.g2d.c;
import com.badlogic.gdx.graphics.i;
import com.badlogic.gdx.math.f;
import java.io.IOException;

public class e extends b {
    h a;
    private a b;
    private com.badlogic.gdx.graphics.g2d.b c;
    private b d;
    private f e;
    private i f;
    private i g;
    private g h;
    private i i;
    private float j = 0.0f;
    private float k = 0.0f;

    static {
        System.loadLibrary("rary");
    }

    public e(h hVar) {
        this.a = hVar;
    }

    public void a() {
        this.c = new c();
        this.c.d();
        this.b = new a();
        try {
            this.e = new f(this.a);
        } catch (IOException e) {
            e.printStackTrace();
            g.a.d();
        }
        this.i = new i(this.e);
        this.d = new b(new f(1408.0f, 2560.0f));
        this.h = new g(this.d, this.e, this.i);
        float b = (float) g.b.b();
        float c = (float) g.b.c();
        this.f = new i(2600.0f, (c / b) * 2600.0f);
        this.g = new i((float) g.b.b(), (float) g.b.c());
        this.g.a.a = b / 2.0f;
        this.g.a.b = c / 2.0f;
        this.g.a();
    }

    public void a(int i, int i2) {
        this.f.j = 2600.0f;
        this.g.j = 2600.0f;
        float f = (((float) i2) * 2600.0f) / ((float) i);
        this.f.k = f;
        this.g.k = f;
    }

    public void b() {
        float d = g.b.d();
        this.j += d;
        this.k += d;
        while (this.k >= 0.016666668f) {
            this.i.a();
            this.i.b();
            this.h.a();
            this.k -= 0.016666668f;
        }
        this.f.a.a(this.d.a, 0.0f);
        com.badlogic.gdx.math.g gVar = this.f.a;
        gVar.b += 300.0f;
        this.f.a();
        g.g.glClearColor(0.0f, 0.0f, 0.0f, 1.0f);
        g.g.glClear((g.b.f().h ? 32768 : 0) | 16640);
        this.c.a();
        this.c.a(this.g.f);
        this.b.a(this.c);
        this.c.a(this.f.f);
        this.e.a(this.c, this.d);
        this.d.a(this.c, this.j);
        this.c.a(this.g.f);
        this.i.a(this.c);
        this.c.b();
    }

    public void e() {
        this.c.c();
    }
}
