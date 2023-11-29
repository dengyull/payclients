package payment.liangdengyu.payclients.ui.notifications;

import static android.Manifest.permission.CAMERA;

import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKeyFromResource;
import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKyberKeyFromResource;
import static payment.liangdengyu.payclients.PreferenceUtil.globaluser;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.math.BigDecimal;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import payment.liangdengyu.payclients.DataEdge;
import payment.liangdengyu.payclients.HttpUtil;
import payment.liangdengyu.payclients.JsonObjectExample;
import payment.liangdengyu.payclients.KeyPairUtils;
import payment.liangdengyu.payclients.LoginActivity;
import payment.liangdengyu.payclients.MainActivity;
import payment.liangdengyu.payclients.PaymentInformation;
import payment.liangdengyu.payclients.PqcChrystalsKyberKem;
import payment.liangdengyu.payclients.PreferenceUtil;
import payment.liangdengyu.payclients.ProductInformation;
import payment.liangdengyu.payclients.R;
import payment.liangdengyu.payclients.User;
import payment.liangdengyu.payclients.databinding.FragmentNotificationsBinding;

public class NotificationsFragment extends Fragment {

    private ListView listProducts;

    private ImageView qrCodeImageView;
    private List<ProductInformation> products;
    private ArrayAdapter<ProductInformation> adapter;
    private static final int CAMERA_REQUEST_CODE = 100;
    private TextView TextView;
    private FragmentNotificationsBinding binding;

    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        NotificationsViewModel notificationsViewModel =
                new ViewModelProvider(this).get(NotificationsViewModel.class);

        binding = FragmentNotificationsBinding.inflate(inflater, container, false);
        View root = binding.getRoot();
        qrCodeImageView = root.findViewById(R.id.imageViewPay);
        Button btnAddProduct = root.findViewById(R.id.btn_add_product);
        listProducts = root.findViewById(R.id.list_products);
        Button btnCreateOrder = root.findViewById(R.id.btn_create_order);
        TextView = root.findViewById(R.id.textViewproduct);
        TextView.setVisibility(View.INVISIBLE);
        products = new ArrayList<>();
        adapter = new ArrayAdapter<>(getContext(), android.R.layout.simple_list_item_1, products);
        listProducts.setAdapter(adapter);
        btnCreateOrder.setVisibility(View.INVISIBLE);
        btnAddProduct.setOnClickListener(v -> startScan(v));
        btnCreateOrder.setOnClickListener(v -> createOrder());
        listProducts.setOnItemClickListener((parent, view1, position, id) -> removeProduct(position));
        return root;
    }
    public void startScan(View view) {
        if (ContextCompat.checkSelfPermission(getContext(), CAMERA) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(getActivity(), new String[]{CAMERA}, CAMERA_REQUEST_CODE);
        } else {
            IntentIntegrator integrator = new IntentIntegrator(getActivity());
            integrator.setCaptureActivity(NotificationsFragment.class);
            integrator.setOrientationLocked(false);
            integrator.setDesiredBarcodeFormats(IntentIntegrator.ONE_D_CODE_TYPES);
            integrator.setPrompt("Scan a barcode");
            integrator.forSupportFragment(this).initiateScan();  // Important change here

        }
    }
    private void createOrder() {

    }


    private void simplesendPostRequest(String data) throws Exception {
        JsonObject json = new JsonObject();
        json.addProperty("data", data);
        JsonObject sentjson = new JsonObject();
        String endpoint = "";
        String mode = PreferenceUtil.getSavedSwitchEncry(getContext());
        switch (mode) {
            case "None":
                sentjson = json;
                endpoint = "/confirmpayment";
                break;
            case "RSA":
                sentjson = DataEdge.rsaJsonEncry(data,getContext());
                endpoint = "/confirmpayment/rsa";
                break;
            case "Kyber":
                if (Security.getProvider("BCPQC") == null) {
                    Security.addProvider(new BouncyCastlePQCProvider());
                }
                endpoint = "/confirmpayment/kyber";
                sentjson = DataEdge.kyberJsonEncry(data,getContext());

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
                    getActivity().runOnUiThread(() -> {
                        AlertDialog.Builder builders = new AlertDialog.Builder(getContext());
                        builders.setMessage("payment successful.")
                                .setTitle("confirm")
                                .setPositiveButton("OK", null);
                        AlertDialog dialog = builders.create();
                        dialog.show();
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

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == CAMERA_REQUEST_CODE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                IntentIntegrator integrator = new IntentIntegrator(getActivity());
                integrator.setCaptureActivity(NotificationsFragment.class);
                integrator.setOrientationLocked(false);
                integrator.setDesiredBarcodeFormats(IntentIntegrator.ONE_D_CODE_TYPES);
                integrator.setPrompt("Scan a barcode");
                integrator.forSupportFragment(this).initiateScan();  // Important change here
            } else {
                Toast.makeText(getContext(), "Camera permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }
    @Override
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
        if (result != null) {
            if (result.getContents() == null) {
                Toast.makeText(getContext(), "Cancelled", Toast.LENGTH_LONG).show();
            } else {
                Gson gson = new Gson();
                JsonObjectExample deserializedObject = gson.fromJson(result.getContents(), JsonObjectExample.class);

                ProductInformation product = fromString(deserializedObject.get("product"));
                try{
                    String savedSwitchTextS = deserializedObject.get("cert");
                    X509Certificate X509Certificate = DataEdge.convertFromPEM(savedSwitchTextS);

                    PublicKey rsaPublicKey = readPublicKeyFromResource(getContext());
                    if(DataEdge.verifyCertificate(X509Certificate,rsaPublicKey)){
                        Log.d("HTTP Response", "verifyCertificate success");
                    } else {
                        Log.d("HTTP Response", "verifyCertificate error");
                    }
                } catch (Exception e) {
                }
                String toid = idfromString(deserializedObject.get("product"));
                PaymentInformation PaymentInformation = new PaymentInformation(PreferenceUtil.globaluser.getId().toString(), PreferenceUtil.globaluser.getPassword(), product.getUnitCost().toString(), toid);
                try {
                    simplegetcu(PaymentInformation.getMerchantAccount());
                } catch (Exception e) {
                }
                String Orderinfo = "Product Mode: "+product.getProductMode()+"\nAmount: 1"+"\nAmount to pay: "+product.getUnitCost();
                JsonObjectExample jsonObject = new JsonObjectExample();
                jsonObject.put("PaymentInformation", PaymentInformation.toJsonString());
                jsonObject.put("Orderinfo", Orderinfo);
                String jsonString = gson.toJson(jsonObject);

                Bitmap qrCodeBitmap = generateQRCode(jsonString);
                //TextView.setText(result.getContents());
                //qrCodeImageView.setImageBitmap(qrCodeBitmap);
                //products.add(product);
                //adapter.notifyDataSetChanged();

                showDialog(this.getContext(),qrCodeBitmap,Orderinfo,jsonObject);
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data);
        }
    }

    public void showDialog(Context context, Bitmap qrCodeBitmap, String message, JsonObjectExample JsonObjectExample) {
        // Create an AlertDialog.Builder instance
        AlertDialog.Builder builder = new AlertDialog.Builder(context);

        // Inflate the custom layout for the dialog
        LayoutInflater inflater = LayoutInflater.from(context);
        View dialogView = inflater.inflate(R.layout.custom_dialog_layout, null);

        // Find views in the custom layout
        ImageView imageView = dialogView.findViewById(R.id.dialog_image);
        TextView messageView = dialogView.findViewById(R.id.dialog_message);

        // Set the image resource dynamically
        imageView.setImageBitmap(qrCodeBitmap);

        // Set the dialog title and message
        builder.setTitle("Create Payment")
                .setView(dialogView) // Set the custom layout
                .setMessage(message);

        // Add a positive button with a click listener
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                // Handle the button click (if needed)
                try {
                    simplesendPostRequest(JsonObjectExample.get("PaymentInformation"));
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                dialog.dismiss(); // Dismiss the dialog*/
            }
        });

        // Create and show the AlertDialog
        AlertDialog dialog = builder.create();
        dialog.show();
    }
    public Bitmap generateQRCode(String text) {
        int width = 500; // Width of the QR code
        int height = 500; // Height of the QR code
        BitMatrix bitMatrix;
        try {
            bitMatrix = new MultiFormatWriter().encode(text, BarcodeFormat.QR_CODE, width, height);
            int bitMatrixWidth = bitMatrix.getWidth();
            int bitMatrixHeight = bitMatrix.getHeight();
            Bitmap bitmap = Bitmap.createBitmap(bitMatrixWidth, bitMatrixHeight, Bitmap.Config.RGB_565);
            for (int x = 0; x < bitMatrixWidth; x++) {
                for (int y = 0; y < bitMatrixHeight; y++) {
                    bitmap.setPixel(x, y, bitMatrix.get(x, y) ? android.graphics.Color.BLACK : android.graphics.Color.WHITE);
                }
            }
            return bitmap;
        } catch (WriterException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ProductInformation fromString(String str) {
        String[] lines = str.split("\n");

        if (lines.length != 4) {
            throw new IllegalArgumentException("Invalid string format for ProductInformation");
        }

        String productMode = lines[0].split(":")[1].trim();
        String manufacturer = lines[1].split(":")[1].trim();
        BigDecimal unitCost = new BigDecimal(lines[2].split(":")[1].trim());

        return new ProductInformation(productMode, manufacturer, unitCost);
    }
    public static String idfromString(String str) {
        String[] lines = str.split("\n");

        if (lines.length != 4) {
            throw new IllegalArgumentException("Invalid string format for ProductInformation");
        }

        String id = lines[3].split(":")[1].trim();

        return id;
    }
    private void simplegetcu(String id) throws Exception {
        JsonObject json = new JsonObject();
        String mode = PreferenceUtil.getSavedSwitchSign(getContext());
        json.addProperty("id", id);
        json.addProperty("mode", mode);
        HttpUtil.sendStringToWebsite("http://dengyu.me:8080/api/payment/getcer", json.toString(), new HttpUtil.Callback() {
            @Override
            public void onSuccess(String response) {
                // Process successful response
                try {
                    X509Certificate cert = DataEdge.convertFromPEM(response);
                    simplegetcu(new PublicKeyCallback() {
                        @Override
                        public void onSuccess(PublicKey publicKey) {
                            // Handle successful retrieval and processing of the public key
                            if(DataEdge.verifyCertificate(cert,publicKey)){
                                Log.d("HTTP Response", "verifyCertificate success");
                            } else {
                                Log.d("HTTP Response", "verifyCertificate error");
                            }
                        }

                        @Override
                        public void onFailure(Exception e) {
                            // Handle failure
                        }
                    });
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                // Handle error
                getActivity().runOnUiThread(() -> {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
                    builder.setMessage("no certificate")
                            .setTitle("certificate load fail")
                            .setPositiveButton("OK", null);
                    AlertDialog dialog = builder.create();
                    dialog.show();
                });
            }
        });
    }
    private void simplegetcu(PublicKeyCallback callback) {
        JsonObject json = new JsonObject();
        String mode = PreferenceUtil.getSavedSwitchSign(getContext());
        json.addProperty("mode", mode);

        HttpUtil.sendStringToWebsite("http://dengyu.me:8080/api/payment/getpublic", json.toString(), new HttpUtil.Callback() {
            @Override
            public void onSuccess(String response) {
                try {
                    byte[] publicBytes = Base64.decode(response, Base64.NO_WRAP);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                    PublicKey publicKey = null;

                    switch (mode) {
                        case "RSA":
                            KeyFactory keyFactoryRSA = KeyFactory.getInstance("RSA");
                            publicKey = keyFactoryRSA.generatePublic(keySpec);
                            break;
                        case "Dilithium":
                            KeyFactory keyFactory = KeyFactory.getInstance("Dilithium", "BCPQC");
                            publicKey = keyFactory.generatePublic(keySpec);
                            break;
                        case "Falcon":
                            KeyFactory dilithiumKeyFactory = KeyFactory.getInstance("FALCON-1024", "BCPQC");
                            publicKey = dilithiumKeyFactory.generatePublic(keySpec);
                            break;
                        default:
                            // Handle default case or throw an exception
                    }

                    if (publicKey != null) {
                        callback.onSuccess(publicKey);
                    } else {
                        callback.onFailure(new Exception("Public key is null"));
                    }
                } catch (Exception e) {
                    callback.onFailure(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                callback.onFailure(e);
            }
        });
    }

    private void removeProduct(int position) {
        products.remove(position);
        adapter.notifyDataSetChanged();
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }
    public interface PublicKeyCallback {
        void onSuccess(PublicKey publicKey);
        void onFailure(Exception e);
    }

}