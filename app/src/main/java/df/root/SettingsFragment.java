package df.root;

import android.content.ComponentName;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Bundle;

import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.SwitchPreferenceCompat;

public class SettingsFragment extends PreferenceFragmentCompat {

    @Override
    public void onCreatePreferences(Bundle savedInstanceState, String rootKey) {
        setPreferencesFromResource(R.xml.preferences, rootKey);

        Context ctx = requireContext();
        SharedPreferences dePrefs = ctx.createDeviceProtectedStorageContext()
                .getSharedPreferences(ExploitRunner.PREFS_NAME, Context.MODE_PRIVATE);

        ComponentName bootReceiver = new ComponentName(ctx, BootReceiver.class);
        SwitchPreferenceCompat bootPref = findPreference("boot_start");
        bootPref.setPersistent(false);
        int state = ctx.getPackageManager().getComponentEnabledSetting(bootReceiver);
        bootPref.setChecked(state == PackageManager.COMPONENT_ENABLED_STATE_ENABLED);
        bootPref.setOnPreferenceChangeListener((pref, value) -> {
            ctx.getPackageManager().setComponentEnabledSetting(bootReceiver,
                    (Boolean) value ? PackageManager.COMPONENT_ENABLED_STATE_ENABLED
                                    : PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
                    PackageManager.DONT_KILL_APP);
            return true;
        });

        SwitchPreferenceCompat softRebootPref = findPreference("soft_reboot");
        softRebootPref.setPersistent(false);
        softRebootPref.setChecked(dePrefs.getBoolean("soft_reboot", false));
        softRebootPref.setOnPreferenceChangeListener((pref, value) -> {
            dePrefs.edit().putBoolean("soft_reboot", (Boolean) value).apply();
            return true;
        });

        SwitchPreferenceCompat disableModulesPref = findPreference("disable_modules");
        disableModulesPref.setPersistent(false);
        disableModulesPref.setChecked(dePrefs.getBoolean("disable_modules", false));
        disableModulesPref.setOnPreferenceChangeListener((pref, value) -> {
            dePrefs.edit().putBoolean("disable_modules", (Boolean) value).apply();
            return true;
        });

        Preference about = findPreference("about");
        if (about != null) {
            about.setSummary(R.string.about_summary);
        }
    }
}
