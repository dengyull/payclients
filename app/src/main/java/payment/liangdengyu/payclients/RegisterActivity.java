package payment.liangdengyu.payclients;

import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKeyFromResource;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonSyntaxException;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class RegisterActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_register);

        String savedSwitchEncry = PreferenceUtil.getSavedSwitchEncry(this);
        String savedSwitchSign = PreferenceUtil.getSavedSwitchSign(this);
        Button bnlogin = findViewById(R.id.register);
        final EditText usernameEditText = findViewById(R.id.usernameregister);
        final EditText passwordEditText = findViewById(R.id.passwordregister);
        usernameEditText.setText("dengyu");
        passwordEditText.setText("denny1998");

        bnlogin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create an Intent to switch to SecondActivity
                sendRequest(usernameEditText.getText().toString(),passwordEditText.getText().toString());

            }
        });
    }

    public JsonObject encry(String mode, JsonObject data) throws Exception {

        JsonObject js = new JsonObject();
        switch (mode) {
            case "None":
                // Handle the case for "Option1"
                return data;
            case "RSA":
                // Handle the case for "Option2"
                DataEdge.aesEncry(data.toString(),this);
            case "Kyber":
                // Handle the case for "Option2"
                DataEdge.aesEncryKyber(data.toString(),this);
            default:
                // Handle the default case where the text doesn't match any known option
        }
        return js;
    }

    private void simplesendPostRequest(String username, String password){
        JsonObject json = new JsonObject();
        json.addProperty("username", username);
        json.addProperty("password", password);
        String endpoint = "";
        String mode = PreferenceUtil.getSavedSwitchEncry(getApplicationContext());
        switch (mode) {
            case "None":
                endpoint = "/registerReq";
                break;
            case "RSA":
                //TODO:json
                endpoint = "/registerReq/rsa";
                break;
            case "Kyber":
                endpoint = "/registerReq/kyber";
                //TODO:json
                break;
            default:
                // Handle the default case where the text doesn't match any known option
        }
        HttpUtil.sendStringToWebsite("http://dengyu.me:8080/api/payment"+endpoint, json.toString(), new HttpUtil.Callback() {
            @Override
            public void onSuccess(String response) {
                // Process successful response

                Gson gson = new Gson();
                User user = gson.fromJson(response, User.class);
                PreferenceUtil.globaluser = user;
                KeyPair keyPair = KeyPairUtils.generateAndSaveKeyPairToFiles(getApplicationContext());
                AsymmetricCipherKeyPair keyPairs = KeyPairUtils.generateAndSaveKyberKeyPairToFiles(getApplicationContext());
                String publicKeyEncoded = Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.NO_WRAP);
                String privateKeyEncoded = Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.NO_WRAP);
                JsonObject jsons = new JsonObject();
                jsons.addProperty("id", PreferenceUtil.globaluser.getId().toString());
                jsons.addProperty("username", username);
                jsons.addProperty("password", password);
                jsons.addProperty("publicKey", publicKeyEncoded);
                jsons.addProperty("privateKey", privateKeyEncoded);
            }

            @Override
            public void onFailure(Exception e) {
                // Handle error
            }
        });
    }

    private void sendRequest(String username, String password) {
        OkHttpClient client = new OkHttpClient();

        // Define request body
        MediaType JSON = MediaType.parse("application/json; charset=utf-8");

        JsonObject json = new JsonObject();
        RequestBody requestBody = RequestBody.create(JSON, json.toString());


        Request request = new Request.Builder()
                .url("http://dengyu.me:8080/api/payment/registerReq")
                .post(requestBody)
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                e.printStackTrace();
                // Handle the error response here

            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {

                if (response.isSuccessful()) {
                    final String responseData = response.body().string();
                    // Handle the successful response here (parse the response, update UI, etc.)
                    try {
                        Gson gson = new Gson();
                        User user = gson.fromJson(responseData, User.class);
                        PreferenceUtil.globaluser = user;
                        // Further processing with the user object...
                    } catch (JsonSyntaxException e) {
                        Log.e("Gson Parsing Error", "Could not parse JSON", e);
                    }
                    //long cpuTimeBefore = System.nanoTime();
                    KeyPair keyPair = KeyPairUtils.generateAndSaveKeyPairToFiles(getApplicationContext());
                    //long cpuTimeAfter = System.nanoTime();
                    //long cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
                    //Log.d("HTTP Response", "rsa keyPair generate time: "+(cpuCost/ 1_000_000)+"ms("+cpuCost+"ns)");

                    //cpuTimeBefore = System.nanoTime();
                    AsymmetricCipherKeyPair keyPairs = KeyPairUtils.generateAndSaveKyberKeyPairToFiles(getApplicationContext());
                    //cpuTimeAfter = System.nanoTime();
                    //cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
                    //Log.d("HTTP Response", "Kyber keyPair generate time: "+(cpuCost/ 1_000_000)+"ms("+cpuCost+"ns)");

                    String publicKeyEncoded = Base64.encodeToString(keyPair.getPublic().getEncoded(), Base64.NO_WRAP);
                    String privateKeyEncoded = Base64.encodeToString(keyPair.getPrivate().getEncoded(), Base64.NO_WRAP);

                    JsonObject jsons = new JsonObject();
                    jsons.addProperty("id", PreferenceUtil.globaluser.getId().toString());
                    jsons.addProperty("username", username);
                    jsons.addProperty("password", password);
                    jsons.addProperty("rsapublicKey", publicKeyEncoded);
                    jsons.addProperty("rsaprivateKey", privateKeyEncoded);
                    try {
                        if (Security.getProvider("BCPQC") == null) {
                            Security.addProvider(new BouncyCastlePQCProvider());
                        }
                        //cpuTimeBefore = System.nanoTime();
                        KeyPair FalconkeyPair = KeyPairUtils.generateAndSaveFalconKeyPairToFiles(getApplicationContext());
                        //cpuTimeAfter = System.nanoTime();
                        //cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
                        //Log.d("HTTP Response", "Falcon keyPair generate time: "+(cpuCost/ 1_000_000)+"ms("+cpuCost+"ns)");
                        String FalconpublicKeyEncoded = Base64.encodeToString(FalconkeyPair.getPublic().getEncoded(), Base64.NO_WRAP);
                        String FalconprivateKeyEncoded = Base64.encodeToString(FalconkeyPair.getPrivate().getEncoded(), Base64.NO_WRAP);
                        //cpuTimeBefore = System.nanoTime();
                        KeyPair DilithiumkeyPair = KeyPairUtils.generateAndSaveDilithiumKeyPairToFiles(getApplicationContext());
                        //cpuTimeAfter = System.nanoTime();
                        //cpuCost = cpuTimeAfter - cpuTimeBefore; // In nanoseconds
                        //Log.d("HTTP Response", "Dilithium keyPair generate time: "+(cpuCost/ 1_000_000)+"ms("+cpuCost+"ns)");
                        String DilithiumpublicKeyEncoded = Base64.encodeToString(DilithiumkeyPair.getPublic().getEncoded(), Base64.NO_WRAP);
                        String DilithiumprivateKeyEncoded = Base64.encodeToString(DilithiumkeyPair.getPrivate().getEncoded(), Base64.NO_WRAP);
                        jsons.addProperty("FalconpublicKey", FalconpublicKeyEncoded);
                        jsons.addProperty("FalconprivateKey", FalconprivateKeyEncoded);
                        jsons.addProperty("DilithiumpublicKey", DilithiumpublicKeyEncoded);
                        jsons.addProperty("DilithiumprivateKey", DilithiumprivateKeyEncoded);
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    RequestBody newrequestBody = RequestBody.create(JSON, jsons.toString());
                    RegisterActivity.this.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            Request newrequest = new Request.Builder()
                                    .url("http://dengyu.me:8080/api/payment/register/rsa")
                                    .post(newrequestBody)
                                    .build();
                            client.newCall(newrequest).enqueue(new Callback(){

                                @Override
                                public void onResponse(@NonNull Call call, @NonNull Response response) throws IOException {

                                    final String responseDatas = response.body().string();
                                    if(responseDatas.equals("user already exist")){
                                        runOnUiThread(new Runnable() {
                                            @Override
                                            public void run() {
                                                AlertDialog.Builder builder = new AlertDialog.Builder(RegisterActivity.this);
                                                builder.setMessage("user already exist")
                                                        .setTitle("register fail")
                                                        .setPositiveButton("OK", null);
                                                AlertDialog dialog = builder.create();
                                                dialog.show();
                                            }
                                        });
                                    } else {

                                        SharedPreferences sharedPref = getSharedPreferences("cert", Context.MODE_PRIVATE);
                                        Gson gson = new Gson();
                                        sentcert sentcert = gson.fromJson(responseDatas, sentcert.class);
                                        SharedPreferences.Editor editor = sharedPref.edit();
                                        editor.putString("rsa cert", sentcert.rsa);
                                        editor.putString("Falcon cert", sentcert.Falcon);
                                        editor.putString("Dilithium cert", sentcert.Dilithium);
                                        editor.apply();


                                        SharedPreferences prefs = getSharedPreferences("cert", Context.MODE_PRIVATE);
                                        String savedSwitchTextS = prefs.getString("rsa cert", "None");
                                        try {
                                            X509Certificate X509Certificate = DataEdge.convertFromPEM(savedSwitchTextS);
                                            PublicKey rsaPublicKey = readPublicKeyFromResource(getApplicationContext());
                                            if(DataEdge.verifyCertificate(X509Certificate,rsaPublicKey)){
                                                Log.d("HTTP Response", "verifyCertificate success");
                                            } else {
                                                Log.d("HTTP Response", "verifyCertificate error");
                                            }
                                        } catch (Exception e) {
                                            throw new RuntimeException(e);
                                        }
                                        PreferenceUtil.globaluser.setUsername(username);
                                        PreferenceUtil.globaluser.setPassword(password);


                                        Intent intent = new Intent(RegisterActivity.this, MainActivity.class);
                                        startActivity(intent);
                                    }
                                }

                                @Override
                                public void onFailure(@NonNull Call call, @NonNull IOException e) {

                                }
                            });

                        }
                    });
                } else {
                    // Handle the error response here
                }
            }
        });
    }
}