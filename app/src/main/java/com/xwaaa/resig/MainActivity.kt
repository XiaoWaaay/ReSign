package com.xwaaa.resig

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.xwaaa.resig.ui.theme.ResigTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException

class MainActivity : ComponentActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            ResigTheme {
                val snackbarHostState = remember { SnackbarHostState() }
                val scope = rememberCoroutineScope()
                val showMessage: (String) -> Unit = { msg ->
                    scope.launch {
                        snackbarHostState.showSnackbar(msg)
                    }
                }

                Scaffold(
                    snackbarHost = { SnackbarHost(hostState = snackbarHostState) }
                ) { padding ->
                    Surface(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        InstalledAppsList(showMessage = showMessage)
                    }
                }
            }
        }
    }

    @Composable
    fun InstalledAppsList(showMessage: (String) -> Unit) {
        val pm = packageManager
        val ctx = LocalContext.current
        val installedApps = getInstalledApps()

        LazyColumn(modifier = Modifier.padding(16.dp)) {
            items(installedApps.size) { index ->
                val pkgInfo = installedApps[index]
                val appName = pkgInfo.applicationInfo.loadLabel(pm).toString()
                val packageName = pkgInfo.packageName
                val sourceApk = pkgInfo.applicationInfo.publicSourceDir ?: pkgInfo.applicationInfo.sourceDir
                // 构造传入 onSignClick 的 Appinfo
                val appinfo = Appinfos(name = appName, packageName = packageName, packagePath = sourceApk, signatures = null)

                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp)
                        .clickable { onAppClick(appName) },
                    shape = MaterialTheme.shapes.medium
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(text = appName, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                text = packageName,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }

                        Button(
                            onClick = {
                                onSignClick(
                                    appName = appName,
                                    appinfo = appinfo,
                                    context = ctx,
                                    packageName = packageName,
                                    showMessage = showMessage
                                )
                            },
                            modifier = Modifier.padding(start = 16.dp)
                        ) {
                            Text("去签")
                        }
                    }
                }
            }
        }
    }

    private fun getInstalledApps(): List<PackageInfo> {
        val pm = packageManager
        @Suppress("DEPRECATION")
        return pm.getInstalledPackages(PackageManager.GET_META_DATA)
            .filter {
                it.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM == 0
            }
            .sortedBy { it.applicationInfo.loadLabel(pm).toString() }
    }

    private fun onAppClick(appName: String) {
        Log.d(TAG, "点击了 $appName")
    }

    private fun onSignClick(
        appName: String,
        appinfo: Appinfos,
        context: Context,
        packageName: String? = null,
        showMessage: (String) -> Unit
    ) {
        showMessage("准备处理 $appName ...")

        // ✅ 使用协程后台执行
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Core(appinfo, context).begin()
                withContext(Dispatchers.Main) {
                    showMessage("$appName 去签完成！")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showMessage("去签失败: ${e.message}")
                }
                Log.e("MainActivity", "去签出错: ${e.message}")
            }
        }
    }

}
