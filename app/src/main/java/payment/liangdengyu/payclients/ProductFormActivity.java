package payment.liangdengyu.payclients;

import androidx.appcompat.app.AppCompatActivity;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;

import java.math.BigDecimal;

import payment.liangdengyu.payclients.R;

public class ProductFormActivity extends AppCompatActivity {
    private EditText editProductMode, editManufacturer, editUnitCost;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_product_form);
        editProductMode = findViewById(R.id.editProductMode);
        editManufacturer = findViewById(R.id.editManufacturer);
        editUnitCost = findViewById(R.id.editUnitCost);
        ProductInformation editProduct = (ProductInformation) getIntent().getSerializableExtra("editProduct");

        if (editProduct != null) {
            // pre-fill the form fields with editProduct's data
            editProductMode.setText(editProduct.getProductMode());
            editManufacturer.setText(editProduct.getManufacturer());
            editUnitCost.setText(editProduct.getUnitCost().toString());
        }

        Button btnSaveProduct = findViewById(R.id.btnSaveProduct);
        btnSaveProduct.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                saveProduct();
            }
        });
    }
    private void saveProduct() {
        String productMode = editProductMode.getText().toString();
        String manufacturer = editManufacturer.getText().toString();
        BigDecimal unitCost = new BigDecimal(editUnitCost.getText().toString());

        ProductInformation product = new ProductInformation(productMode, manufacturer, unitCost);

        Intent resultIntent = new Intent();
        resultIntent.putExtra("product", product);
        setResult(Activity.RESULT_OK, resultIntent);
        finish();
    }
}