package com.example.keystoredemo.crypto

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

object SecretStorageManager {

    private fun getMasterKey(context: Context): MasterKey {
        return MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private fun getEncryptedPrefs(context: Context): SharedPreferences {
        return EncryptedSharedPreferences.create(
            context,
            "demo_secret_prefs",
            getMasterKey(context),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    fun saveSecret(context: Context, key: String, value: String) {
        getEncryptedPrefs(context).edit().putString(key, value).apply()
    }

    fun readSecret(context: Context, key: String): String? {
        return getEncryptedPrefs(context).getString(key, null)
    }

    fun deleteSecret(context: Context, key: String) {
        getEncryptedPrefs(context).edit().remove(key).apply()
    }

    fun listSecrets(context: Context): Map<String, String> {
        val prefs = getEncryptedPrefs(context)
        return prefs.all.mapValues { it.value?.toString() ?: "" }
    }

    fun clearAll(context: Context) {
        getEncryptedPrefs(context).edit().clear().apply()
    }
}
