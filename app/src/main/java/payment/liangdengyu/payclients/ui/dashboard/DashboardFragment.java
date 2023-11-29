package payment.liangdengyu.payclients.ui.dashboard;

import static android.Manifest.permission.CAMERA;

import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKeyFromResource;
import static payment.liangdengyu.payclients.KeyPairUtils.readPublicKyberKeyFromResource;
import static payment.liangdengyu.payclients.PreferenceUtil.globaluser;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
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
import com.google.gson.reflect.TypeToken;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;

import java.io.IOException;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

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
import payment.liangdengyu.payclients.ProductFormActivity;
import payment.liangdengyu.payclients.ProductInformation;
import payment.liangdengyu.payclients.R;
import payment.liangdengyu.payclients.User;
import payment.liangdengyu.payclients.databinding.FragmentDashboardBinding;

public class DashboardFragment extends Fragment {
    private static final int REQUEST_CODE_ADD_PRODUCT = 1;
    private static final int EDIT_CODE_ADD_PRODUCT = 2;
    private static final int CAMERA_REQUEST_CODE = 100;

    private int editposition;
    private ListView productListView;
    private List<ProductInformation> productList = new ArrayList<>();
    private ArrayAdapter<ProductInformation> adapter;
    private FragmentDashboardBinding binding;

    public View onCreateView(@NonNull LayoutInflater inflater,
                             ViewGroup container, Bundle savedInstanceState) {
        DashboardViewModel dashboardViewModel =
                new ViewModelProvider(this).get(DashboardViewModel.class);

        binding = FragmentDashboardBinding.inflate(inflater, container, false);
        View root = binding.getRoot();
        ImageView qrCodeImageView = root.findViewById(R.id.imageViewQrC);
        Bitmap qrCodeBitmap = generateQRCode("Your content goes here");
        //qrCodeImageView.setImageBitmap(qrCodeBitmap);

        productListView = root.findViewById(R.id.productListView);
        loadProducts();
        adapter = new ArrayAdapter<>(getContext(), android.R.layout.simple_list_item_1, productList);
        productListView.setAdapter(adapter);

        productListView.setOnItemClickListener((parent, view, position, id) -> {
            ProductInformation clickedProduct = (ProductInformation) parent.getItemAtPosition(position);
            JsonObjectExample jsonObject = new JsonObjectExample();
            jsonObject.put("product", clickedProduct.sentString());

            SharedPreferences prefs = requireActivity().getSharedPreferences("cert", Context.MODE_PRIVATE);
            String savedSwitchTextS = prefs.getString("cert", "None");
            jsonObject.put("cert", savedSwitchTextS);

            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-384");
                byte[] encodedhash = digest.digest(clickedProduct.sentString().getBytes());

                // Convert byte array into signum representation
                BigInteger number = new BigInteger(1, encodedhash);

                // Convert message digest into hex value
                StringBuilder hexString = new StringBuilder(number.toString(16));


                // Pad with leading zeros
                while (hexString.length() < 64) {
                    hexString.insert(0, '0');
                }
                jsonObject.put("digest", hexString.toString());
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
            Gson gson = new Gson();
            String jsonString = gson.toJson(jsonObject);

            String gen = clickedProduct.sentString();
            Bitmap qrCodeBitmaps = generateQRCode(jsonString);

            //PaymentInformation PaymentInformation = new PaymentInformation(globaluser.getId().toString(),globaluser.getPassword(),clickedProduct.getUnitCost().toString(),"1");
            //sendPostRequest(PaymentInformation.toJsonString());
            qrCodeImageView.setImageBitmap(qrCodeBitmaps);
        });

        productListView.setOnItemLongClickListener((parent, view, position, id) -> {
            ProductInformation selectedProduct = productList.get(position);

            displayEditDeleteDialog(selectedProduct, position);
            return true; // true indicates the event was handled
        });


        Button btnAddProduct = root.findViewById(R.id.btnAddProduct);
        btnAddProduct.setOnClickListener(v -> {
            Intent intent = new Intent(getContext(), ProductFormActivity.class);
            startActivityForResult(intent, REQUEST_CODE_ADD_PRODUCT);
        });

        Button paybutton = root.findViewById(R.id.btnPay);
        paybutton.setOnClickListener(v -> {
            startScan(v);
        });
        return root;
    }

    public void startScan(View view) {
        if (ContextCompat.checkSelfPermission(getContext(), CAMERA) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(getActivity(), new String[]{CAMERA}, CAMERA_REQUEST_CODE);
        } else {
            IntentIntegrator integrator = new IntentIntegrator(getActivity());
            integrator.setCaptureActivity(DashboardFragment.class);
            integrator.setOrientationLocked(false);
            integrator.setDesiredBarcodeFormats(IntentIntegrator.ONE_D_CODE_TYPES);
            integrator.setPrompt("Scan a barcode");
            integrator.forSupportFragment(this).initiateScan();  // Important change here

        }
    }
    private void displayEditDeleteDialog(ProductInformation product, int position) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getContext());
        builder.setTitle("Choose an action")
                .setItems(new String[]{"Edit", "Delete"}, (dialog, which) -> {
                    switch (which) {
                        case 0: // Edit
                            editProduct(product, position);
                            break;
                        case 1: // Delete
                            productList.remove(position);
                            adapter.notifyDataSetChanged();
                            saveProducts(); // Save updated list
                            break;
                    }
                })
                .show();
    }

    private void editProduct(ProductInformation product, int position) {
        // Here you can launch an activity or dialog to edit the product
        // After editing, update your productList and adapter, then save it
        editposition = position;
        Intent intent = new Intent(getContext(), ProductFormActivity.class);
        intent.putExtra("editProduct", product);  // Sending the product for editing
        startActivityForResult(intent, EDIT_CODE_ADD_PRODUCT);
    }


    private void saveProducts() {
        SharedPreferences sharedPreferences = getActivity().getSharedPreferences("ProductPrefs", Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = sharedPreferences.edit();

        Gson gson = new Gson();
        String json = gson.toJson(productList);
        editor.putString("productList", json);
        editor.apply();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == CAMERA_REQUEST_CODE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                IntentIntegrator integrator = new IntentIntegrator(getActivity());
                integrator.setCaptureActivity(DashboardFragment.class);
                integrator.setOrientationLocked(false);
                integrator.setDesiredBarcodeFormats(IntentIntegrator.ONE_D_CODE_TYPES);
                integrator.setPrompt("Scan a barcode");
                integrator.forSupportFragment(this).initiateScan();  // Important change here
            } else {
                Toast.makeText(getContext(), "Camera permission denied", Toast.LENGTH_SHORT).show();
            }
        }
    }
    private void loadProducts() {
        SharedPreferences sharedPreferences = getActivity().getSharedPreferences("ProductPrefs", Context.MODE_PRIVATE);
        String json = sharedPreferences.getString("productList", null);

        if (json != null) {
            Gson gson = new Gson();
            Type type = new TypeToken<List<ProductInformation>>() {}.getType();
            productList = gson.fromJson(json, type);
        }
    }


    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
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

    public static PaymentInformation fromJsonString(String jsonString) {
        Gson gson = new Gson();
        return gson.fromJson(jsonString, PaymentInformation.class);
    }
    public void onActivityResult(int requestCode, int resultCode, @Nullable Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_CODE_ADD_PRODUCT && resultCode == getActivity().RESULT_OK && data != null) {
            ProductInformation product = (ProductInformation) data.getSerializableExtra("product");
            productList.add(product);
            saveProducts();
            adapter.notifyDataSetChanged();
        } else if (requestCode == EDIT_CODE_ADD_PRODUCT && resultCode == getActivity().RESULT_OK && data != null){
            ProductInformation product = (ProductInformation) data.getSerializableExtra("product");
            productList.get(editposition).setProductMode(product.getProductMode());
            productList.get(editposition).setManufacturer(product.getManufacturer());
            productList.get(editposition).setUnitCost(product.getUnitCost());
            saveProducts();
            adapter.notifyDataSetChanged();
        } else {
            IntentResult result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data);
            if (result != null) {
                if (result.getContents() == null) {
                    Toast.makeText(getContext(), "Cancelled", Toast.LENGTH_LONG).show();
                } else {
                    //Toast.makeText(getContext(), "Scanned: " + result.getContents(), Toast.LENGTH_LONG).show();
                    Gson gson = new Gson();
                    JsonObjectExample deserializedObject = gson.fromJson(result.getContents(), JsonObjectExample.class);
                    PaymentInformation product = gson.fromJson((deserializedObject.get("PaymentInformation")),PaymentInformation.class);//fromString(result.getContents());
                    try {
                        simplegetcu(product.getMerchantAccount());
                    } catch (Exception e) {
                    }
                    showDialog(this.getContext(),"confirm order",deserializedObject.get("Orderinfo"),product);
                    //sendPostRequest(product.getPaymentAmount(),product.getAlternatePassword(),product.getDisbursementAccount(),product.getPaymentAmount());
                    //adapter.notifyDataSetChanged();
                }
            } else {
            }
        }

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
                endpoint = "/createpayment";
                break;
            case "RSA":
                sentjson = DataEdge.rsaJsonEncry(data,getContext());
                endpoint = "/createpayment/rsa";
                break;
            case "Kyber":
                if (Security.getProvider("BCPQC") == null) {
                    Security.addProvider(new BouncyCastlePQCProvider());
                }
                endpoint = "/createpayment/kyber";
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
                        builders.setMessage("please wait for customer pay.")
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
                    builder.setMessage("error user or network")
                            .setTitle("login fail")
                            .setPositiveButton("OK", null);
                    AlertDialog dialog = builder.create();
                    dialog.show();
                });
            }
        });
    }

    public void showDialog(Context context, String title, String message, PaymentInformation PaymentInformation) {
        // Create an AlertDialog.Builder instance
        AlertDialog.Builder builder = new AlertDialog.Builder(context);

        // Set the dialog title and message
        builder.setTitle(title)
                .setMessage(message);

        // Add a positive button with a click listener
        builder.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int id) {
                // Handle the button click (if needed)
                if (Security.getProvider("BCPQC") == null) {
                    Security.addProvider(new BouncyCastlePQCProvider());
                }
                try {
                    simplesendPostRequest(PaymentInformation.toJsonString());
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                dialog.dismiss(); // Dismiss the dialog
            }
        });

        // Create and show the AlertDialog
        AlertDialog dialog = builder.create();
        dialog.show();
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
                    Gson gson = new Gson();
                    String modes = PreferenceUtil.getSavedSwitchSign(getContext());
                    X509Certificate X509Certificate = DataEdge.convertFromPEM(response);
                    switch (modes){
                        case "None":
                            break;
                        case "RSA":
                            PublicKey rsaPublicKey = readPublicKeyFromResource(getContext());
                            if(DataEdge.verifyCertificate(X509Certificate,rsaPublicKey)){
                                Log.d("HTTP Response", "verifyCertificate success");
                            } else {
                                Log.d("HTTP Response", "verifyCertificate error");
                            }
                            break;
                        case "Dilithium":
                            PublicKey DilithiumPublicKey = readPublicKeyFromResource(getContext());
                            if(DataEdge.verifyCertificate(X509Certificate,DilithiumPublicKey)){
                                Log.d("HTTP Response", "verifyCertificate success");
                            } else {
                                Log.d("HTTP Response", "verifyCertificate error");
                            }
                            break;
                        case "Falcon":
                            PublicKey FalconPublicKey = readPublicKeyFromResource(getContext());
                            Log.d("HTTP Response", FalconPublicKey.toString());
                            if(DataEdge.verifyCertificate(X509Certificate,FalconPublicKey)){
                                Log.d("HTTP Response", "verifyCertificate success");
                            } else {
                                Log.d("HTTP Response", "verifyCertificate error");
                            }
                            break;
                        default:
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public void onFailure(Exception e) {
                // Handle error
//                Log.d("HTTP Response", e.toString());
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
}