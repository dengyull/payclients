package payment.liangdengyu.payclients.ui.home;

import static payment.liangdengyu.payclients.PreferenceUtil.globaluser;

import android.app.AlertDialog;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.gson.JsonObject;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.math.BigDecimal;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

import payment.liangdengyu.payclients.DataEdge;
import payment.liangdengyu.payclients.HttpUtil;
import payment.liangdengyu.payclients.PreferenceUtil;
import payment.liangdengyu.payclients.R;
import payment.liangdengyu.payclients.User;
import payment.liangdengyu.payclients.databinding.FragmentHomeBinding;
import payment.liangdengyu.payclients.ui.notifications.NotificationsFragment;

public class HomeFragment extends Fragment {
    private TextView textAmount;
    private EditText inputAmount;
    private FragmentHomeBinding binding;
    private User user;
    private BigDecimal currentAmount = BigDecimal.valueOf(0.0);


    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        HomeViewModel homeViewModel =
                new ViewModelProvider(this).get(HomeViewModel.class);

        binding = FragmentHomeBinding.inflate(inflater, container, false);
        View root = binding.getRoot();
        textAmount = root.findViewById(R.id.textAmount);
        inputAmount = root.findViewById(R.id.inputAmount);
        Button buttonSave = root.findViewById(R.id.buttonSave);
        Button buttonWithdraw = root.findViewById(R.id.buttonWithdraw);
        currentAmount = PreferenceUtil.globaluser.getAmount();
        //sendPostRequest();
        try {
            postbalance();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        updateAmountDisplay();
        buttonSave.setOnClickListener(v -> {
            try {
                if (inputAmount.getText().toString()==""){
                    AlertDialog.Builder builders = new AlertDialog.Builder(getContext());
                    builders.setMessage(new String("please input amount to deposit."))
                            .setTitle("confirm")
                            .setPositiveButton("OK", null);
                    AlertDialog dialog = builders.create();
                    dialog.show();
                } else {
                    simplesendPostRequest(inputAmount.getText().toString());
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        buttonWithdraw.setOnClickListener(v -> {
            try {
                if (inputAmount.getText().toString()==""){
                    AlertDialog.Builder builders = new AlertDialog.Builder(getContext());
                    builders.setMessage(new String("please input amount to withdraw."))
                            .setTitle("confirm")
                            .setPositiveButton("OK", null);
                    AlertDialog dialog = builders.create();
                    dialog.show();
                } else{
                    simplesendPostRequest("-"+inputAmount.getText().toString());
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
        return root;
    }
    private void simplesendPostRequest(String amount) throws Exception {
        JsonObject json = new JsonObject();
        json.addProperty("id", globaluser.getId().toString());
        json.addProperty("username", globaluser.getUsername());
        json.addProperty("password", globaluser.getPassword());
        json.addProperty("amount", amount);
        JsonObject sentjson = new JsonObject();
        String endpoint = "";
        String mode = PreferenceUtil.getSavedSwitchEncry(getContext());
        switch (mode) {
            case "None":
                sentjson = json;
                endpoint = "/userSave";
                break;
            case "RSA":
                sentjson = DataEdge.rsaJsonEncry(json.toString(),getContext());
                endpoint = "/userSave/rsa";
                break;
            case "Kyber":
                if (Security.getProvider("BCPQC") == null) {
                    Security.addProvider(new BouncyCastlePQCProvider());
                }
                endpoint = "/userSave/kyber";
                sentjson = DataEdge.kyberJsonEncry(json.toString(),getContext());

                break;
        }
        HttpUtil.sendStringToWebsite("http://dengyu.me:8080/api/payment"+endpoint, sentjson.toString(), new HttpUtil.Callback() {
            @Override
            public void onSuccess(String response) {
                // Process successful response
                try {
                    String modes = PreferenceUtil.getSavedSwitchEncry(getContext());
                    String sentback;
                    switch (modes){
                        case "None":
                            sentback = response;
                            break;
                        default:
                            byte[] sentbackbyte = DataEdge.aesdecrypted(response);
                            sentback = new String(sentbackbyte);
                    }
                    currentAmount = new BigDecimal(sentback);
                    globaluser.setAmount(currentAmount);
                    getActivity().runOnUiThread(() -> {
                        updateAmountDisplay();
                        AlertDialog.Builder builders = new AlertDialog.Builder(getContext());
                        builders.setMessage(sentback)
                                .setTitle("confirm")
                                .setPositiveButton("OK", null);
                        AlertDialog dialog = builders.create();
                        dialog.show();
                    });
                } catch (Exception e) {
                    getActivity().runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                            builder.setMessage("error response data")
                                    .setTitle("error response data")
                                    .setPositiveButton("OK", null);
                            AlertDialog dialog = builder.create();
                            dialog.show();
                        }
                    });
                }
            }

            @Override
            public void onFailure(Exception e) {
                // Handle error
                getActivity().runOnUiThread(() -> {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                    builder.setMessage("error user")
                            .setTitle("login fail")
                            .setPositiveButton("OK", null);
                    AlertDialog dialog = builder.create();
                    dialog.show();
                });
            }
        });
    }

    private void postbalance() throws Exception {
        JsonObject json = new JsonObject();
        json.addProperty("username", globaluser.getUsername());
        json.addProperty("password", globaluser.getPassword());
        JsonObject sentjson = new JsonObject();
        String endpoint = "";
        String mode = PreferenceUtil.getSavedSwitchEncry(getContext());
        sentjson = json;
        endpoint = "/balance";
        HttpUtil.sendStringToWebsite("http://dengyu.me:8080/api/payment"+endpoint, sentjson.toString(), new HttpUtil.Callback() {
            @Override
            public void onSuccess(String response) {
                // Process successful response
                try {
                    String modes = PreferenceUtil.getSavedSwitchEncry(getContext());
                    currentAmount = new BigDecimal(response);
                    getActivity().runOnUiThread(() -> {
                        updateAmountDisplay();
                    });
                } catch (Exception e) {
                    getActivity().runOnUiThread(() -> {
                        AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                        builder.setMessage("error response data")
                                .setTitle("error response data")
                                .setPositiveButton("OK", null);
                        AlertDialog dialog = builder.create();
                        dialog.show();
                    });
                }
            }

            @Override
            public void onFailure(Exception e) {
                // Handle error
                getActivity().runOnUiThread(() -> {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                    builder.setMessage("error user")
                            .setTitle("login fail")
                            .setPositiveButton("OK", null);
                    AlertDialog dialog = builder.create();
                    dialog.show();
                });
            }
        });
    }

    private void updateAmountDisplay() {
        textAmount.setText("Balance: $" + currentAmount);
    }


    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }
}