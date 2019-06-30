package com.google.ctf.game;

import com.badlogic.gdx.g;
import com.badlogic.gdx.graphics.g2d.b;
import com.badlogic.gdx.graphics.l;

class a {
    l a = new l(g.e.a("scenery.png"));

    a() {
    }

    /* Access modifiers changed, original: 0000 */
    public void a(b bVar) {
        for (int i = 0; i < (g.b.c() / this.a.b()) + 1; i++) {
            for (int i2 = 0; i2 < (g.b.b() / this.a.a()) + 1; i2++) {
                bVar.a(this.a, ((float) Math.round(((float) (this.a.a() * i2)) * 10.0f)) / 10.0f, ((float) Math.round(((float) (this.a.b() * i)) * 10.0f)) / 10.0f);
            }
        }
    }
}
