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
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import com.xwaaa.resig.ui.theme.ResigTheme
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {

    companion object {
        private const val TAG = "MainActivity"
    }

    @OptIn(ExperimentalMaterial3Api::class)
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
                    topBar = {
                        CenterAlignedTopAppBar(
                            title = { Text("重打包安全检查") }
                        )
                    },
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

    private data class InstalledAppRow(
        val appName: String,
        val packageName: String,
        val sourceApk: String
    )

    @Composable
    fun InstalledAppsList(showMessage: (String) -> Unit) {
        val pm = packageManager
        val ctx = LocalContext.current
        val prefs = remember(ctx) { ctx.getSharedPreferences("resig_ui", Context.MODE_PRIVATE) }
        var query by remember { mutableStateOf("") }
        var enableJavaHook by remember { mutableStateOf(true) }
        var enableNativeIo by remember { mutableStateOf(true) }
        var enableMapsHide by remember { mutableStateOf(prefs.getBoolean("enableMapsHide", false)) }
        var debugLog by remember { mutableStateOf(prefs.getBoolean("debugLog", false)) }
        var hookMode by remember { mutableStateOf(prefs.getString("hookMode", "standard") ?: "standard") }
        var enableDeepHide by remember { mutableStateOf(prefs.getBoolean("enableDeepHide", false)) }
        var enableCache by remember { mutableStateOf(true) }
        var advancedExpanded by remember { mutableStateOf(false) }

        val installedApps = remember {
            getInstalledApps().map { pkgInfo ->
                val appName = pkgInfo.applicationInfo.loadLabel(pm).toString()
                val packageName = pkgInfo.packageName
                val sourceApk =
                    pkgInfo.applicationInfo.publicSourceDir ?: pkgInfo.applicationInfo.sourceDir
                InstalledAppRow(appName = appName, packageName = packageName, sourceApk = sourceApk)
            }
        }

        val filteredApps = remember(query, installedApps) {
            val q = query.trim()
            if (q.isEmpty()) {
                installedApps
            } else {
                installedApps.filter { app ->
                    app.appName.contains(q, ignoreCase = true) ||
                        app.packageName.contains(q, ignoreCase = true)
                }
            }
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
        ) {
            Spacer(modifier = Modifier.height(4.dp))

            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                label = { Text("搜索") },
                placeholder = { Text("按应用名或包名过滤") },
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        TextButton(onClick = { query = "" }) {
                            Text("清除")
                        }
                    }
                }
            )

            Text(text = "运行期开关", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(6.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(checked = enableJavaHook, onCheckedChange = { enableJavaHook = it })
                Text(text = "启用 Java Hook")
                Spacer(modifier = Modifier.width(12.dp))
                Checkbox(checked = enableNativeIo, onCheckedChange = { enableNativeIo = it })
                Text(text = "启用 Native IO 重定向")
            }

            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "Native 后端由运行期模式决定（SAFE=PLT，STANDARD/AGGRESSIVE=Hybrid）",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Text(text = "运行期模式", style = MaterialTheme.typography.titleSmall)
            Spacer(modifier = Modifier.height(6.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(
                    selected = hookMode == "safe",
                    onClick = {
                        hookMode = "safe"
                        prefs.edit().putString("hookMode", hookMode).apply()
                    }
                )
                Text(text = "SAFE")
                Spacer(modifier = Modifier.width(10.dp))
                RadioButton(
                    selected = hookMode == "standard",
                    onClick = {
                        hookMode = "standard"
                        prefs.edit().putString("hookMode", hookMode).apply()
                    }
                )
                Text(text = "STANDARD")
                Spacer(modifier = Modifier.width(10.dp))
                RadioButton(
                    selected = hookMode == "aggressive",
                    onClick = {
                        hookMode = "aggressive"
                        prefs.edit().putString("hookMode", hookMode).apply()
                    }
                )
                Text(text = "AGGRESSIVE")
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(text = "高级选项", style = MaterialTheme.typography.titleSmall)
                TextButton(onClick = { advancedExpanded = !advancedExpanded }) {
                    Text(if (advancedExpanded) "收起" else "展开")
                }
            }

            if (advancedExpanded) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = debugLog,
                        onCheckedChange = {
                            debugLog = it
                            prefs.edit().putBoolean("debugLog", it).apply()
                        }
                    )
                    Text(text = "debugLog")
                    Spacer(modifier = Modifier.width(12.dp))
                    Checkbox(
                        checked = enableCache,
                        onCheckedChange = { enableCache = it }
                    )
                    Text(text = "启用缓存")
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    val mapsEnabled = enableNativeIo && hookMode == "aggressive"
                    Checkbox(
                        checked = enableMapsHide && mapsEnabled,
                        enabled = mapsEnabled,
                        onCheckedChange = {
                            enableMapsHide = it
                            prefs.edit().putBoolean("enableMapsHide", it).apply()
                        }
                    )
                    Text(text = "maps 隐藏（仅 AGGRESSIVE）")
                }

                Row(verticalAlignment = Alignment.CenterVertically) {
                    val deepHideEnabled = hookMode != "safe"
                    Checkbox(
                        checked = enableDeepHide && deepHideEnabled,
                        enabled = deepHideEnabled,
                        onCheckedChange = {
                            enableDeepHide = it
                            prefs.edit().putBoolean("enableDeepHide", it).apply()
                        }
                    )
                    Text(text = "Deep Hide（高风险，SAFE 不启用）")
                }
            }

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "已安装应用：${filteredApps.size}",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(12.dp))

            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(filteredApps.size) { index ->
                    val app = filteredApps[index]
                    val appinfo = Appinfos(
                        name = app.appName,
                        packageName = app.packageName,
                        packagePath = app.sourceApk,
                        signatures = null
                    )

                    Card(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp)
                            .clickable { onAppClick(app.appName) },
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
                                Text(text = app.appName, style = MaterialTheme.typography.bodyLarge)
                                Text(
                                    text = app.packageName,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                                Spacer(modifier = Modifier.height(4.dp))
                            }

                            Button(
                                onClick = {
                                    val enableJava = enableJavaHook
                                    val enableNative = enableNativeIo
                                    val enableIo = enableNativeIo
                                    val enableMaps = enableNativeIo && hookMode == "aggressive" && enableMapsHide
                                    val dbg = debugLog
                                    val mode = hookMode
                                    val deepHide = hookMode != "safe" && enableDeepHide
                                    val cache = enableCache

                                    val options = Core.Options().apply {
                                        enableJavaHook = enableJava
                                        enableNativeHook = enableNative
                                        enableIoRedirect = enableIo
                                        enableMapsHide = enableMaps
                                        enableResourceRedirect = false
                                        debugLog = dbg
                                        hookMode = mode
                                        enableDeepHide = deepHide
                                        enableCache = cache
                                        enablePayloadDexCache = cache
                                    }
                                    onRepackClick(
                                        appName = app.appName,
                                        appinfo = appinfo,
                                        context = ctx,
                                        options = options,
                                        showMessage = showMessage
                                    )
                                },
                                modifier = Modifier.padding(start = 16.dp)
                            ) {
                                Text("重打包")
                            }
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

    private fun onRepackClick(
        appName: String,
        appinfo: Appinfos,
        context: Context,
        options: Core.Options,
        showMessage: (String) -> Unit
    ) {
        showMessage("准备处理 $appName ...")

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                Core(appinfo, context, options).begin()
                withContext(Dispatchers.Main) {
                    showMessage("$appName 完成！")
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showMessage("处理失败: ${e.message}")
                }
                Log.e("MainActivity", "处理出错: ${e.message}")
            }
        }
    }

}
