package com.kypeli.mtlspoc

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.kypeli.mtlspoc.ui.MainView
import com.kypeli.mtlspoc.ui.MainViewModel
import com.kypeli.mtlspoc.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels {
        viewModelFactory {
            initializer {
                (application as MtlsApplication).appGraph.mainViewModel
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val context = LocalContext.current
            val uiState by viewModel.uiState.collectAsState()

            val localNetworkPermissionLauncher =
                rememberLauncherForActivityResult(
                    ActivityResultContracts.RequestPermission(),
                ) { granted ->
                    if (granted) {
                        viewModel.connect()
                    } else {
                        viewModel.onLocalNetworkPermissionDenied()
                    }
                }

            MyApplicationTheme {
                MainView(
                    uiState = uiState,
                    onConnect = {
                        if (!isLocalNetworkProtectionEnforced() || hasLocalNetworkPermission(context)) {
                            viewModel.connect()
                        } else {
                            localNetworkPermissionLauncher.launch(Manifest.permission.ACCESS_LOCAL_NETWORK)
                        }
                    },
                )
            }
        }
    }

    /**
     * Local Network Protection (Android 17, API 37+): every local network access is gated
     * behind [Manifest.permission.ACCESS_LOCAL_NETWORK], which Android enforces by silently
     * dropping local-network traffic when it is not granted. The permission belongs to the
     * NEARBY_DEVICES group, so users who already granted a sibling permission (such as a
     * Bluetooth permission) are not re-prompted.
     */
    private fun hasLocalNetworkPermission(context: Context): Boolean =
        context.checkSelfPermission(Manifest.permission.ACCESS_LOCAL_NETWORK) ==
            PackageManager.PERMISSION_GRANTED

    /**
     * ACCESS_LOCAL_NETWORK only exists on Android 16+/17+ (API 36/37). Checking or requesting
     * it on older platforms is invalid and can crash, so the gate is skipped there.
     */
    private fun isLocalNetworkProtectionEnforced(): Boolean = Build.VERSION.SDK_INT >= 37
}
