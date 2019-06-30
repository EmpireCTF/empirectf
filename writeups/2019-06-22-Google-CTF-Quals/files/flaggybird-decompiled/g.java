package com.google.ctf.game;

import com.badlogic.gdx.math.f;

class g {
    private f a;
    private i b;
    private b c;

    g(b bVar, f fVar, i iVar) {
        this.a = fVar;
        this.b = iVar;
        this.c = bVar;
    }

    /* JADX WARNING: Removed duplicated region for block: B:49:? A:{SYNTHETIC, RETURN, SKIP} */
    /* JADX WARNING: Removed duplicated region for block: B:45:0x0145  */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    private void a(c cVar) {
        cVar.c += 0.9f;
        f fVar = cVar.a;
        fVar.e -= cVar.c;
        int i = ((int) (cVar.a.e + cVar.b.e)) / this.a.f;
        int i2 = ((int) (cVar.a.e + (cVar.b.e / 2.0f))) / this.a.f;
        int i3 = ((int) cVar.a.e) / this.a.f;
        int i4 = ((int) cVar.a.d) / this.a.e;
        int i5 = ((int) (cVar.a.d + (cVar.b.d / 2.0f))) / this.a.e;
        int i6 = ((int) (cVar.a.d + cVar.b.d)) / this.a.e;
        Object obj = ((this.a.c[i3][i4] == a.GROUND && this.a.c[i3][i5] == a.GROUND) || (this.a.c[i3][i6] == a.GROUND && this.a.c[i3][i5] == a.GROUND)) ? 1 : null;
        Object obj2 = ((this.a.c[i][i4] == a.GROUND && this.a.c[i][i5] == a.GROUND) || (this.a.c[i][i6] == a.GROUND && this.a.c[i][i5] == a.GROUND)) ? 1 : null;
        Object obj3 = this.a.c[i2][i4] == a.GROUND ? 1 : null;
        Object obj4 = this.a.c[i2][i6] == a.GROUND ? 1 : null;
        if (obj2 != null) {
            cVar.a.e = (float) (this.a.f * (i - 1));
            cVar.c = 0.0f;
        } else if (obj != null) {
            cVar.a.e = (float) (this.a.f * (i3 + 1));
            cVar.c = 0.0f;
            cVar.f = false;
        }
        if (this.b.c()) {
            if (obj3 == null) {
                fVar = cVar.a;
                fVar.d -= 10.0f;
                cVar.d = false;
            }
            if (!this.b.e() && !cVar.f) {
                cVar.c = -28.0f;
                cVar.f = true;
                return;
            }
            return;
        }
        if (!this.b.d()) {
            cVar.e = false;
        } else if (obj4 == null) {
            fVar = cVar.a;
            fVar.d += 10.0f;
            cVar.d = true;
        }
        if (!this.b.e()) {
            return;
        }
        return;
        cVar.e = true;
        if (!this.b.e()) {
        }
    }

    /* Access modifiers changed, original: 0000 */
    public void a() {
        a(this.c);
        if (this.b.f()) {
            int i = ((int) (this.c.a.e + (this.c.b.e / 2.0f))) / this.a.f;
            int i2 = ((int) this.c.a.d) / this.a.e;
            int i3 = ((int) (this.c.a.d + (this.c.b.d / 2.0f))) / this.a.e;
            int i4 = ((int) (this.c.a.d + this.c.b.d)) / this.a.e;
            if (this.a.c[i][i2] == a.COMPUTER || this.a.c[i][i3] == a.COMPUTER || this.a.c[i][i4] == a.COMPUTER) {
                this.a.a();
            } else if (this.a.c[i][i2] == a.PORTAL || this.a.c[i][i3] == a.PORTAL || this.a.c[i][i4] == a.PORTAL) {
                this.a.a(this.c);
            } else {
                if (this.a.c[i][i2] != a.EGG_HOLDER) {
                    if (this.a.c[i][i3] == a.EGG_HOLDER) {
                        i2 = i3;
                    } else if (this.a.c[i][i4] == a.EGG_HOLDER) {
                        i2 = i4;
                    } else {
                        return;
                    }
                }
                this.b.d(this.a.d[i][i2]);
            }
        }
    }
}
