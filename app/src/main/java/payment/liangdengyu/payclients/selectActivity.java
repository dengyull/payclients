package payment.liangdengyu.payclients;

import androidx.appcompat.app.AppCompatActivity;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.RadioButton;
import android.widget.RadioGroup;

public class selectActivity extends AppCompatActivity {

    private RadioGroup switchGroup, switchGroup2;
    private SharedPreferences sharedPreferences;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_select);

        switchGroup = findViewById(R.id.radioGroupFirst);
        switchGroup2 = findViewById(R.id.radioGroupSecond);
        Button saveButton = findViewById(R.id.buttonSave);

        sharedPreferences = getSharedPreferences("AppPrefs", MODE_PRIVATE);
        loadSavedPreferences();

        saveButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                int selectedId = switchGroup.getCheckedRadioButtonId();
                savePreferences("SavedSwitchEncry", selectedId);
                RadioButton selectedButton = findViewById(switchGroup.getCheckedRadioButtonId());
                String selectedButtonText = selectedButton != null ? selectedButton.getText().toString() : "";
                savePreferences("SavedSwitchEncryText", selectedButtonText);

                int selectedIdS = switchGroup2.getCheckedRadioButtonId();
                savePreferences("SavedSwitchSign", selectedIdS);
                RadioButton selectedButtonS = findViewById(switchGroup2.getCheckedRadioButtonId());
                String selectedButtonTextS = selectedButtonS != null ? selectedButtonS.getText().toString() : "";
                savePreferences("SavedSwitchSignText", selectedButtonTextS);

            }
        });
        switchGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup group, int checkedId) {
                // Assuming radioGroupA_Button1 is the ID of the first button in RadioGroup A
                onChecked(checkedId);
            }
        });
    }
    public void onChecked(int checkedId) {
        // Assuming radioGroupA_Button1 is the ID of the first button in RadioGroup A
        if (checkedId == R.id.radioNoneFirst) {
            findViewById(R.id.radioNoneSecond).setEnabled(true);
            switchGroup2.check(findViewById(R.id.radioNoneSecond).getId());
            findViewById(R.id.radioRSASecond).setEnabled(false);
            findViewById(R.id.radioDilithium).setEnabled(false);
            findViewById(R.id.radioFalcon).setEnabled(false);
            // Optionally disable other buttons in RadioGroup B
        } else if (checkedId == R.id.radioRSAFirst) {
            // If another button in Group A is selected, change the state of buttons in Group B
            findViewById(R.id.radioNoneSecond).setEnabled(false);
            findViewById(R.id.radioRSASecond).setEnabled(true);
            switchGroup2.check(findViewById(R.id.radioRSASecond).getId());
            findViewById(R.id.radioDilithium).setEnabled(false);
            findViewById(R.id.radioFalcon).setEnabled(false);
            // Optionally reset or enable other buttons in RadioGroup B
        } else if (checkedId == R.id.radioKyber) {
            // If another button in Group A is selected, change the state of buttons in Group B
            findViewById(R.id.radioNoneSecond).setEnabled(false);
            findViewById(R.id.radioRSASecond).setEnabled(false);
            switchGroup2.check(findViewById(R.id.radioDilithium).getId());
            findViewById(R.id.radioDilithium).setEnabled(true);
            findViewById(R.id.radioFalcon).setEnabled(true);
            // Optionally reset or enable other buttons in RadioGroup B
        }
    }

    private void loadSavedPreferences() {
        int savedSwitchId = sharedPreferences.getInt("SavedSwitchEncry", -1);
        if (savedSwitchId != -1) {
            RadioButton savedCheckedRadioButton = findViewById(savedSwitchId);
            onChecked(savedSwitchId);
            savedCheckedRadioButton.setChecked(true);
        }
        int savedSwitchIdS = sharedPreferences.getInt("SavedSwitchSign", -1);
        if (savedSwitchIdS != -1) {
            RadioButton savedCheckedRadioButton = findViewById(savedSwitchIdS);
            savedCheckedRadioButton.setChecked(true);
        }
    }
    private void savePreferences(String key, int value) {
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putInt(key, value);
        editor.apply();
    }

    private void savePreferences(String key, String value) {
        SharedPreferences.Editor editor = sharedPreferences.edit();
        editor.putString(key, value);
        editor.apply();
    }
}