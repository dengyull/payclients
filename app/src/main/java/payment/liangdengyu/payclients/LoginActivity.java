package payment.liangdengyu.payclients;

import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKyberKeyFromResource;

import androidx.appcompat.app.AppCompatActivity;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class LoginActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);
        final EditText usernameEditText = findViewById(R.id.usernamelogin);
        final EditText passwordEditText = findViewById(R.id.passwordlogin);
        final Button loginButton = findViewById(R.id.login);
        usernameEditText.setText("dengyu");
        passwordEditText.setText("denny1998");

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                try {
                    simplesendPostRequest(usernameEditText.getText().toString(),
                            passwordEditText.getText().toString());
                } catch (Exception e) {
                    //Log.d("HTTP Response", e.toString());
                }
            }
        });
    }

    private void simplesendPostRequest(String username, String password) throws Exception {
        JsonObject json = new JsonObject();
        json.addProperty("username", username);
        json.addProperty("password", password);
        JsonObject sentjson = new JsonObject();
        String endpoint = "";
        String mode = PreferenceUtil.getSavedSwitchEncry(getApplicationContext());
        switch (mode) {
            case "None":
                sentjson = json;
                long currentTimeMillis = System.currentTimeMillis();
                sentjson.addProperty("timestamp", currentTimeMillis);
                endpoint = "/login";
                break;
            case "RSA":
                sentjson = DataEdge.rsaJsonEncry(json.toString(),getApplicationContext());
                endpoint = "/login/rsa";
                break;
            case "Kyber":
                if (Security.getProvider("BCPQC") == null) {
                    Security.addProvider(new BouncyCastlePQCProvider());
                }
                endpoint = "/login/kyber";
                sentjson = DataEdge.kyberJsonEncry(json.toString(),getApplicationContext());

                break;
        }
        HttpUtil.sendStringToWebsite("http://dengyu.me:8080/api/payment"+endpoint, sentjson.toString(), new HttpUtil.Callback() {
            @Override
            public void onSuccess(String response) {
                // Process successful response
                try {
                    Gson gson = new Gson();
                    String modes = PreferenceUtil.getSavedSwitchEncry(getApplicationContext());
                    switch (modes){
                        case "None":
                            PreferenceUtil.globaluser = gson.fromJson(response, User.class);
                            break;
                        default:
                            byte[] sentbackbyte = DataEdge.aesdecrypted(response);
                            PreferenceUtil.globaluser = gson.fromJson(new String(sentbackbyte), User.class);
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                Intent intent = new Intent(LoginActivity.this, MainActivity.class);
                intent.putExtra("bigDecimalValue", PreferenceUtil.globaluser.getAmount().toString());
                startActivity(intent);
            }

            @Override
            public void onFailure(Exception e) {
                // Handle error
                //Log.d("HTTP Response", e.toString());
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        AlertDialog.Builder builder = new AlertDialog.Builder(LoginActivity.this);
                        builder.setMessage("error user")
                                .setTitle("login fail")
                                .setPositiveButton("OK", null);
                        AlertDialog dialog = builder.create();
                        dialog.show();
                    }
                });
            }
        });
    }




    private void sendPostRequest(String username, String password) {
        OkHttpClient client = new OkHttpClient();

        // Define request body
        MediaType JSON = MediaType.parse("application/json; charset=utf-8");

        JsonObject json = new JsonObject();
        json.addProperty("username", username);
        json.addProperty("password", password);
        RequestBody requestBody = RequestBody.create(JSON, json.toString());


        Request request = new Request.Builder()
                .url("http://dengyu.me:8080/api/test/login")
                .post(requestBody)
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();
                // Handle the error response here
                //Log.d("HTTP Response", e.toString());

            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {

                if (response.isSuccessful()) {
                    final String responseData = response.body().string();
                    // Handle the successful response here (parse the response, update UI, etc.)
                    Gson gson = new Gson();
                    PreferenceUtil.globaluser = gson.fromJson(responseData, User.class);
                    Intent intent = new Intent(LoginActivity.this, MainActivity.class);
                    startActivity(intent);
                } else {
                    // Handle the error response here
                    // Inside an Activity or Fragment:
                    runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            AlertDialog.Builder builder = new AlertDialog.Builder(LoginActivity.this);
                            builder.setMessage("error user")
                                    .setTitle("login fail")
                                    .setPositiveButton("OK", null);
                            AlertDialog dialog = builder.create();
                            dialog.show();
                        }
                    });


                }
            }
        });
    }
}