package hackit.secretkeeper.altair;

import android.os.Bundle;
import android.os.StrictMode;
import android.os.StrictMode.ThreadPolicy;
import android.support.design.widget.FloatingActionButton;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.EditText;
import android.widget.TextView;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import okhttp3.OkHttpClient;
import okhttp3.Request.Builder;
import org.json.JSONObject;

public class MainActivity extends AppCompatActivity {
    String base = "185.168.131.121";
    OkHttpClient client = new OkHttpClient();
    Magix magix = new Magix(100000);

    /* renamed from: hackit.secretkeeper.altair.MainActivity$1 */
    class C03221 implements OnClickListener {
        C03221() {
        }

        public void onClick(View view) {
            try {
                TextView textView = (TextView) MainActivity.this.findViewById(C0323R.id.textView1);
                EditText editText = (EditText) MainActivity.this.findViewById(C0323R.id.editText1);
                JSONObject jSONObject = new JSONObject(MainActivity.this.run("encryptor"));
                StringBuilder stringBuilder = new StringBuilder();
                stringBuilder.append(jSONObject.getString("p"));
                stringBuilder.append(editText.getText());
                String encode = URLEncoder.encode(new Magix(100000, new ByteArrayInputStream(stringBuilder.toString().getBytes(StandardCharsets.UTF_8))).doMagic(jSONObject.getString("result")), "utf-8");
                MainActivity mainActivity = MainActivity.this;
                StringBuilder stringBuilder2 = new StringBuilder();
                stringBuilder2.append("?spell=");
                stringBuilder2.append(encode);
                textView.setText(new JSONObject(mainActivity.run(stringBuilder2.toString())).getString("result"));
            } catch (View view2) {
                view2.printStackTrace();
            } catch (View view22) {
                view22.printStackTrace();
            } catch (View view222) {
                view222.printStackTrace();
            }
        }
    }

    String run(String str) throws IOException {
        Builder builder = new Builder();
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("http://");
        stringBuilder.append(this.base);
        stringBuilder.append("/");
        stringBuilder.append(str);
        return this.client.newCall(builder.url(stringBuilder.toString()).build()).execute().body().string();
    }

    protected void onCreate(Bundle bundle) {
        StrictMode.setThreadPolicy(new ThreadPolicy.Builder().permitAll().build());
        super.onCreate(bundle);
        setContentView((int) C0323R.layout.activity_main);
        setSupportActionBar((Toolbar) findViewById(C0323R.id.toolbar));
        ((FloatingActionButton) findViewById(C0323R.id.fab)).setOnClickListener(new C03221());
    }

    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(C0323R.menu.menu_main, menu);
        return true;
    }

    public boolean onOptionsItemSelected(MenuItem menuItem) {
        if (menuItem.getItemId() == C0323R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(menuItem);
    }
}
