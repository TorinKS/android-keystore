package com.example.keystoredemo

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.example.keystoredemo.ui.screens.*
import com.example.keystoredemo.ui.theme.KeystoreDemoTheme

class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            KeystoreDemoTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    val navController = rememberNavController()
                    NavHost(navController = navController, startDestination = "home") {
                        composable("home") {
                            HomeScreen(onNavigate = { navController.navigate(it) })
                        }
                        composable("keygen") {
                            KeyGenScreen(onBack = { navController.popBackStack() })
                        }
                        composable("protection") {
                            KeyProtectionScreen(onBack = { navController.popBackStack() })
                        }
                        composable("encrypt") {
                            EncryptDecryptScreen(onBack = { navController.popBackStack() })
                        }
                        composable("sign") {
                            SignVerifyScreen(onBack = { navController.popBackStack() })
                        }
                        composable("secrets") {
                            SecretStorageScreen(onBack = { navController.popBackStack() })
                        }
                        composable("attestation") {
                            KeyAttestationScreen(onBack = { navController.popBackStack() })
                        }
                        composable("keys") {
                            KeyListScreen(onBack = { navController.popBackStack() })
                        }
                    }
                }
            }
        }
    }
}
