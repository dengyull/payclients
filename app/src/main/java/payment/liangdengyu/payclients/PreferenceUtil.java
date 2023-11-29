package payment.liangdengyu.payclients;

import android.content.Context;
import android.content.SharedPreferences;

public class PreferenceUtil {

    private static final String PREFS_NAME = "AppPrefs";
    public static User globaluser;

    public static String getSavedSwitchEncry(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String savedSwitchText = prefs.getString("SavedSwitchEncryText", "None");
        return savedSwitchText;
    }

    public static String getSavedSwitchSign(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        String savedSwitchTextS = prefs.getString("SavedSwitchSignText", "None");
        return savedSwitchTextS;
    }
}
