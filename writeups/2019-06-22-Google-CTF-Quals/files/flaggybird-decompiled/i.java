package com.google.ctf.game;

import com.badlogic.gdx.g;
import com.badlogic.gdx.graphics.g2d.b;
import com.badlogic.gdx.graphics.g2d.d;
import com.badlogic.gdx.graphics.l;
import com.badlogic.gdx.j;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

class i extends j {
    private d a;
    private d b;
    private d c;
    private d d;
    private List<d> e = new ArrayList();
    private List<d> f;
    private boolean g;
    private int h;
    private f i;

    i(f fVar) {
        f fVar2 = fVar;
        this.i = fVar2;
        l lVar = new l(g.e.a("ui.png"));
        int a = lVar.a() / 4;
        int b = lVar.b() / 2;
        d[][] a2 = d.a(lVar, a, b);
        int b2 = g.b.b();
        int c = g.b.c();
        this.a = new d(a2[1][1], 16, 16, a);
        this.e.add(this.a);
        int i = 0;
        this.b = new d(a2[1][0], a + 32, 16, a);
        this.e.add(this.b);
        int i2 = (b2 - 16) - a;
        this.c = new d(a2[1][2], i2, 16, a);
        this.e.add(this.c);
        this.d = new d(a2[1][3], i2, b + 32, a);
        this.e.add(this.d);
        this.f = new ArrayList();
        int i3 = 0;
        while (i3 < f.a.length) {
            int i4 = (i3 % 4) * a;
            int i5 = (i3 / 4) * b;
            ArrayList arrayList = new ArrayList();
            arrayList.add(a2[i][i]);
            arrayList.add(fVar2.a(f.a[i3]));
            int i6 = ((b2 / 2) - (a * 2)) + i4;
            int i7 = ((c / 2) - (b * 2)) + i5;
            d dVar = r4;
            List list = this.f;
            d dVar2 = new d(arrayList, i6, i7, a, i3);
            list.add(dVar);
            i3++;
            i = 0;
        }
        this.g = false;
        this.h = 0;
    }

    private void g() {
        this.g = false;
    }

    /* Access modifiers changed, original: 0000 */
    public void a() {
        int i;
        Iterator it = this.e.iterator();
        while (true) {
            i = 0;
            if (!it.hasNext()) {
                break;
            }
            ((d) it.next()).a = false;
        }
        for (d dVar : this.f) {
            dVar.a = false;
        }
        while (i < 20) {
            if (g.d.c(i)) {
                int a = g.d.a(i);
                int c = g.b.c() - g.d.b(i);
                if (this.g) {
                    for (d a2 : this.f) {
                        a2.a(a, c);
                    }
                } else {
                    for (d a22 : this.e) {
                        a22.a(a, c);
                    }
                }
            }
            i++;
        }
    }

    /* Access modifiers changed, original: 0000 */
    public void a(b bVar) {
        for (d a : this.e) {
            a.a(bVar);
        }
        if (this.g) {
            for (d a2 : this.f) {
                a2.a(bVar);
            }
        }
    }

    /* Access modifiers changed, original: 0000 */
    public void b() {
        if (this.g) {
            for (d dVar : this.f) {
                if (dVar.a) {
                    this.i.a(this.h, dVar.b);
                    g();
                    break;
                }
            }
        }
    }

    /* Access modifiers changed, original: 0000 */
    public boolean c() {
        return !this.g && (g.d.d(21) || this.a.a);
    }

    /* Access modifiers changed, original: 0000 */
    public void d(int i) {
        this.g = true;
        this.h = i;
    }

    /* Access modifiers changed, original: 0000 */
    public boolean d() {
        return !this.g && (g.d.d(22) || this.b.a);
    }

    /* Access modifiers changed, original: 0000 */
    public boolean e() {
        return !this.g && (g.d.e(62) || this.c.a);
    }

    /* Access modifiers changed, original: 0000 */
    public boolean f() {
        return g.d.e(52) || this.d.a;
    }
}
