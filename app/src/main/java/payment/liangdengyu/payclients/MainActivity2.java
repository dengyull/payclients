package payment.liangdengyu.payclients;

import static payment.liangdengyu.payclients.KeyPairUtils.readKyberPublicKeyFromFile;
import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKeyFromResource;
import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKyberKeyFromResource;
import static payment.liangdengyu.payclients.PqcChrystalsKyberKem.run;
import static payment.liangdengyu.payclients.PqcChrystalsKyberKem.run2;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import com.google.gson.JsonObject;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.security.GeneralSecurityException;
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

public class MainActivity2 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main2);

        Button bnlogsele = findViewById(R.id.buttonToSelect);
        bnlogsele.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create an Intent to switch to SecondActivity
                Intent intent = new Intent(MainActivity2.this, selectActivity.class);
                startActivity(intent);
            }
        });
        Button bnlogin = findViewById(R.id.Btnlogin);
        bnlogin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create an Intent to switch to SecondActivity
                Intent intent = new Intent(MainActivity2.this, LoginActivity.class);
                startActivity(intent);
            }
        });
        Button bnreg = findViewById(R.id.btnreg);
        bnreg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create an Intent to switch to SecondActivity
                Intent intent = new Intent(MainActivity2.this, RegisterActivity.class);
                startActivity(intent);
            }
        });
        Button bntest = findViewById(R.id.buttontested);
        bntest.setVisibility(View.INVISIBLE);
        bntest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (Security.getProvider("BCPQC") == null) {
                    Security.addProvider(new BouncyCastlePQCProvider());
                }

                SharedPreferences prefs = getSharedPreferences("cert", Context.MODE_PRIVATE);
                String savedSwitchTextS = prefs.getString("cert", "None");
                X509Certificate X509Certificate = null;
                try {
                    X509Certificate = DataEdge.convertFromPEM(savedSwitchTextS);

                    PublicKey rsaPublicKey = readPublicKeyFromResource(getApplicationContext());
                    /*Log.d("HTTP Response", rsaPublicKey.toString());
                    if(DataEdge.verifyCertificate(X509Certificate,rsaPublicKey)){
                        Log.d("HTTP Response", "verifyCertificate success");
                    } else {
                        Log.d("HTTP Response", "verifyCertificate error");
                    }*/
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                /*
                // Create an Intent to switch to SecondActivity
                try {
                    String mode = PreferenceUtil.getSavedSwitchEncry(getApplicationContext());
                    switch (mode) {
                        case "None":
                            // Handle the case for "Option1"
                            sendPostRequest("");
                            break;
                        case "RSA":
                            // Handle the case for "Option2"
                            sendPostRequestrsa("smart");
                            break;
                        case "Kyber":
                            // Handle the case for "Option2"
                            sendPostRequestkyber("cat");
                            break;
                        default:
                            // Handle the default case where the text doesn't match any known option
                    }
                } catch (GeneralSecurityException e) {
                    throw new RuntimeException(e);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }*/


            }
        });
    }
}