package com.google.ctf.game;

import com.badlogic.gdx.g;
import com.badlogic.gdx.graphics.g2d.a;
import com.badlogic.gdx.graphics.g2d.d;
import com.badlogic.gdx.graphics.l;
import com.badlogic.gdx.math.f;

class b extends c {
    private a<d> g;
    private d[] h = new d[5];

    b(f fVar) {
        super(fVar);
        l lVar = new l(g.e.a("bird.png"));
        int a = lVar.a() / 8;
        int b = lVar.b() / 1;
        a(new f((float) a, (float) (b / 2)));
        d[][] a2 = d.a(lVar, a, b);
        System.arraycopy(a2[0], 0, this.h, 0, this.h.length);
        this.g = new a(0.075f, this.h);
    }

    /* Access modifiers changed, original: 0000 */
    public void a(com.badlogic.gdx.graphics.g2d.b bVar, float f) {
        if (!this.e) {
            f = 0.0f;
        }
        d dVar = this.f ? this.h[2] : (d) this.g.a(f, true);
        dVar.a(this.d ^ 1, false);
        bVar.a(dVar, this.a.d, this.a.e);
        if (!this.d) {
            dVar.a(true, false);
        }
    }
}
