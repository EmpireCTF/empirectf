package com.google.ctf.game;

import android.os.Bundle;
import android.widget.Toast;
import com.badlogic.gdx.backends.android.a;
import com.badlogic.gdx.c;

public class AndroidLauncher extends a implements h {
    public void a(final String str) {
        runOnUiThread(new Runnable() {
            public void run() {
                Toast.makeText(AndroidLauncher.this.getApplicationContext(), str, 1).show();
            }
        });
    }

    /* Access modifiers changed, original: protected */
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        a((c) new e(this), new com.badlogic.gdx.backends.android.c());
    }
}
