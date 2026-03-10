/**
 * ReSignPro - MainActivity
 *
 * 主界面：Jetpack Compose 实现
 * 功能：应用列表、重打包配置、进度显示、日志查看
 */
package com.resign.pro.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.graphics.drawable.toBitmap
import com.resign.pro.core.PackEngine
import com.resign.pro.ui.theme.ReSignProTheme
import com.resign.pro.ui.theme.SuccessGreen
import com.resign.pro.util.AppInfoHelper
import com.resign.pro.util.FileUtils
import com.resign.pro.util.Logger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 请求存储权限
        requestPermissions()

        setContent {
            ReSignProTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen()
                }
            }
        }
    }

    private fun requestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!android.os.Environment.isExternalStorageManager()) {
                try {
                    val intent = android.content.Intent(
                        android.provider.Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION
                    )
                    startActivity(intent)
                } catch (e: Exception) {
                    Logger.e("MainActivity", "Failed to request MANAGE_EXTERNAL_STORAGE", e)
                }
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(
                    arrayOf(
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                    ), 100
                )
            }
        }
    }
}

// ==================== Main Screen ====================

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    // 状态
    var selectedTab by remember { mutableIntStateOf(0) }
    var appList by remember { mutableStateOf<List<AppInfoHelper.AppItem>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var selectedApp by remember { mutableStateOf<AppInfoHelper.AppItem?>(null) }
    var showConfigDialog by remember { mutableStateOf(false) }

    // 重打包状态
    var isRepacking by remember { mutableStateOf(false) }
    var repackProgress by remember { mutableFloatStateOf(0f) }
    var repackStatus by remember { mutableStateOf("") }
    var repackLogs by remember { mutableStateOf<List<String>>(emptyList()) }
    var repackResult by remember { mutableStateOf<String?>(null) }

    // 配置
    var hookMode by remember { mutableStateOf(PackEngine.HookMode.STANDARD) }
    var nativeBackend by remember { mutableStateOf("plt_hook") }
    var enableAntiDetect by remember { mutableStateOf(true) }
    var preserveSignBlock by remember { mutableStateOf(true) }

    // 加载应用列表
    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            appList = AppInfoHelper.getInstalledApps(context)
            isLoading = false
        }
    }

    // APK 文件选择器
    val apkPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let {
            scope.launch(Dispatchers.IO) {
                val tmpFile = File(FileUtils.getWorkDir(context), "import.apk")
                FileUtils.copyUriToFile(context, it, tmpFile)
                val info = AppInfoHelper.getApkInfo(context, tmpFile.absolutePath)
                if (info != null) {
                    selectedApp = info
                    withContext(Dispatchers.Main) { showConfigDialog = true }
                }
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text("ReSignPro", fontWeight = FontWeight.Bold)
                },
                actions = {
                    IconButton(onClick = { apkPicker.launch("application/vnd.android.package-archive") }) {
                        Icon(Icons.Filled.FolderOpen, contentDescription = "选择 APK")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.Apps, contentDescription = null) },
                    label = { Text("应用") },
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.Build, contentDescription = null) },
                    label = { Text("重打包") },
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.Terminal, contentDescription = null) },
                    label = { Text("日志") },
                    selected = selectedTab == 2,
                    onClick = { selectedTab = 2 }
                )
            }
        }
    ) { paddingValues ->
        Box(modifier = Modifier.padding(paddingValues)) {
            when (selectedTab) {
                0 -> AppListTab(
                    appList = appList,
                    isLoading = isLoading,
                    onAppSelected = {
                        selectedApp = it
                        showConfigDialog = true
                    }
                )
                1 -> RepackTab(
                    isRepacking = isRepacking,
                    progress = repackProgress,
                    status = repackStatus,
                    result = repackResult
                )
                2 -> LogTab(logs = repackLogs)
            }
        }
    }

    // 配置对话框
    if (showConfigDialog && selectedApp != null) {
        RepackConfigDialog(
            app = selectedApp!!,
            hookMode = hookMode,
            nativeBackend = nativeBackend,
            enableAntiDetect = enableAntiDetect,
            preserveSignBlock = preserveSignBlock,
            onHookModeChanged = { hookMode = it },
            onNativeBackendChanged = { nativeBackend = it },
            onAntiDetectChanged = { enableAntiDetect = it },
            onPreserveSignBlockChanged = { preserveSignBlock = it },
            onConfirm = {
                showConfigDialog = false
                isRepacking = true
                selectedTab = 1
                repackLogs = emptyList()
                repackResult = null

                scope.launch(Dispatchers.IO) {
                    try {
                        val config = PackEngine.Config().apply {
                            this.hookMode = hookMode
                            this.nativeBackend = when (nativeBackend) {
                                "seccomp" -> PackEngine.NativeBackend.SECCOMP
                                "hybrid" -> PackEngine.NativeBackend.HYBRID
                                else -> PackEngine.NativeBackend.PLT
                            }
                            this.enableDeepHide = enableAntiDetect
                            this.enableMapsHide = enableAntiDetect && hookMode == PackEngine.HookMode.AGGRESSIVE
                            this.preserveSigningBlock = preserveSignBlock
                        }

                        val engine = PackEngine(context, config)
                        engine.setProgressCallback(object : PackEngine.ProgressCallback {
                            override fun onProgress(step: Int, total: Int, message: String) {
                                val p = if (total > 0) step.toFloat() / total.toFloat() else 0f
                                repackProgress = p
                                repackStatus = message
                                repackLogs = repackLogs + "[${String.format("%.0f", p * 100)}%] $message"
                            }

                            override fun onError(error: String) {
                                repackLogs = repackLogs + "[ERROR] $error"
                            }

                            override fun onComplete(outputPath: String) {
                                repackResult = outputPath
                                repackLogs = repackLogs + "[DONE] 输出: $outputPath"
                            }
                        })

                        val outputPath = engine.repack(selectedApp!!.packageName)
                        repackResult = outputPath

                    } catch (e: Exception) {
                        repackLogs = repackLogs + "[FATAL] ${e.message}"
                        Logger.e("Repack", "Repack failed", e)
                    } finally {
                        isRepacking = false
                    }
                }
            },
            onDismiss = { showConfigDialog = false }
        )
    }
}

// ==================== App List Tab ====================

@Composable
fun AppListTab(
    appList: List<AppInfoHelper.AppItem>,
    isLoading: Boolean,
    onAppSelected: (AppInfoHelper.AppItem) -> Unit
) {
    var searchQuery by remember { mutableStateOf("") }
    val filteredList = remember(appList, searchQuery) {
        if (searchQuery.isEmpty()) appList
        else appList.filter {
            it.appName.contains(searchQuery, ignoreCase = true) ||
            it.packageName.contains(searchQuery, ignoreCase = true)
        }
    }

    Column(modifier = Modifier.fillMaxSize()) {
        // 搜索栏
        OutlinedTextField(
            value = searchQuery,
            onValueChange = { searchQuery = it },
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            placeholder = { Text("搜索应用名或包名...") },
            leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
            trailingIcon = {
                if (searchQuery.isNotEmpty()) {
                    IconButton(onClick = { searchQuery = "" }) {
                        Icon(Icons.Filled.Clear, contentDescription = "清除")
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(12.dp)
        )

        if (isLoading) {
            Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.height(16.dp))
                    Text("正在加载应用列表...")
                }
            }
        } else {
            Text(
                text = "共 ${filteredList.size} 个应用",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
            )

            LazyColumn(modifier = Modifier.fillMaxSize()) {
                items(filteredList, key = { it.packageName }) { app ->
                    AppListItem(app = app, onClick = { onAppSelected(app) })
                }
            }
        }
    }
}

@Composable
fun AppListItem(app: AppInfoHelper.AppItem, onClick: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 4.dp)
            .clickable(onClick = onClick),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 应用图标
            app.icon?.let { drawable ->
                Image(
                    bitmap = drawable.toBitmap(48, 48).asImageBitmap(),
                    contentDescription = app.appName,
                    modifier = Modifier
                        .size(48.dp)
                        .clip(RoundedCornerShape(12.dp))
                )
            } ?: Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(MaterialTheme.colorScheme.primaryContainer),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = app.appName.take(1),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onPrimaryContainer
                )
            }

            Spacer(modifier = Modifier.width(12.dp))

            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = app.appName,
                        style = MaterialTheme.typography.titleSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f, fill = false)
                    )
                    if (app.hasSplits) {
                        Spacer(modifier = Modifier.width(4.dp))
                        SuggestionChip(
                            onClick = {},
                            label = { Text("Split", style = MaterialTheme.typography.labelSmall) },
                            modifier = Modifier.height(20.dp)
                        )
                    }
                }
                Text(
                    text = app.packageName,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Row {
                    Text(
                        text = "v${app.versionName}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "API ${app.targetSdkVersion}",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = FileUtils.humanReadableSize(app.fileSize),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            Icon(
                Icons.Filled.ChevronRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

// ==================== Repack Config Dialog ====================

@Composable
fun RepackConfigDialog(
    app: AppInfoHelper.AppItem,
    hookMode: PackEngine.HookMode,
    nativeBackend: String,
    enableAntiDetect: Boolean,
    preserveSignBlock: Boolean,
    onHookModeChanged: (PackEngine.HookMode) -> Unit,
    onNativeBackendChanged: (String) -> Unit,
    onAntiDetectChanged: (Boolean) -> Unit,
    onPreserveSignBlockChanged: (Boolean) -> Unit,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("重打包配置") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // 应用信息
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Text(app.appName, style = MaterialTheme.typography.titleSmall)
                        Text(app.packageName, style = MaterialTheme.typography.bodySmall)
                        Text("v${app.versionName} | API ${app.targetSdkVersion}",
                             style = MaterialTheme.typography.labelSmall)
                    }
                }

                // Hook 模式选择
                Text("Hook 模式", style = MaterialTheme.typography.titleSmall)
                PackEngine.HookMode.values().forEach { mode ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onHookModeChanged(mode) }
                            .padding(vertical = 4.dp)
                    ) {
                        RadioButton(
                            selected = hookMode == mode,
                            onClick = { onHookModeChanged(mode) }
                        )
                        Column(modifier = Modifier.padding(start = 8.dp)) {
                            Text(mode.name, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                when (mode) {
                                    PackEngine.HookMode.SAFE -> "仅基本签名欺骗，兼容性最好"
                                    PackEngine.HookMode.STANDARD -> "标准模式，覆盖大部分检测"
                                    PackEngine.HookMode.AGGRESSIVE -> "激进模式，全量 Hook + IPC 代理"
                                },
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Divider()

                // Native 后端
                Text("Native 后端", style = MaterialTheme.typography.titleSmall)
                listOf(
                    "plt_hook" to "PLT Hook (推荐，兼容性好)",
                    "seccomp" to "Seccomp BPF (拦截直接syscall)",
                    "hybrid" to "混合模式 (PLT + Seccomp)"
                ).forEach { (value, desc) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onNativeBackendChanged(value) }
                            .padding(vertical = 4.dp)
                    ) {
                        RadioButton(
                            selected = nativeBackend == value,
                            onClick = { onNativeBackendChanged(value) }
                        )
                        Text(desc, style = MaterialTheme.typography.bodySmall,
                             modifier = Modifier.padding(start = 8.dp))
                    }
                }

                Divider()

                // 开关选项
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("反检测", style = MaterialTheme.typography.bodyMedium)
                        Text("隐藏重打包痕迹", style = MaterialTheme.typography.labelSmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(checked = enableAntiDetect, onCheckedChange = onAntiDetectChanged)
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text("保留签名块", style = MaterialTheme.typography.bodyMedium)
                        Text("保留原始 V2/V3 签名块结构", style = MaterialTheme.typography.labelSmall,
                             color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(checked = preserveSignBlock, onCheckedChange = onPreserveSignBlockChanged)
                }
            }
        },
        confirmButton = {
            Button(onClick = onConfirm) {
                Text("开始重打包")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("取消")
            }
        }
    )
}

// ==================== Repack Progress Tab ====================

@Composable
fun RepackTab(
    isRepacking: Boolean,
    progress: Float,
    status: String,
    result: String?
) {
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        if (isRepacking) {
            CircularProgressIndicator(
                progress = progress,
                modifier = Modifier.size(120.dp),
                strokeWidth = 8.dp,
            )
            Spacer(modifier = Modifier.height(24.dp))
            Text(
                text = "${(progress * 100).toInt()}%",
                style = MaterialTheme.typography.headlineLarge,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = status,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(24.dp))
            LinearProgressIndicator(
                progress = progress,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(8.dp)
                    .clip(RoundedCornerShape(4.dp)),
            )
        } else if (result != null) {
            Icon(
                Icons.Filled.CheckCircle,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = SuccessGreen
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text("重打包完成!", style = MaterialTheme.typography.headlineSmall)
            Spacer(modifier = Modifier.height(8.dp))
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("输出文件:", style = MaterialTheme.typography.labelMedium)
                    Text(
                        text = result,
                        style = MaterialTheme.typography.bodySmall,
                        textAlign = TextAlign.Start
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            val outFile = remember(result) { File(result) }
            val outDir = remember(result) { File(result).parentFile }

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = {
                        openApk(context, outFile)
                    }
                ) {
                    Icon(Icons.Filled.OpenInNew, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("打开")
                }

                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = {
                        shareApk(context, outFile)
                    }
                ) {
                    Icon(Icons.Filled.Share, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("分享")
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = {
                        copyText(context, result)
                    }
                ) {
                    Icon(Icons.Filled.ContentCopy, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("复制路径")
                }

                OutlinedButton(
                    modifier = Modifier.weight(1f),
                    onClick = {
                        if (outDir != null) {
                            openFolder(context, outDir)
                        } else {
                            Toast.makeText(context, "目录不存在", Toast.LENGTH_SHORT).show()
                        }
                    }
                ) {
                    Icon(Icons.Filled.FolderOpen, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("打开目录")
                }
            }
        } else {
            Icon(
                Icons.Outlined.Build,
                contentDescription = null,
                modifier = Modifier.size(80.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
            )
            Spacer(modifier = Modifier.height(16.dp))
            Text(
                "选择一个应用开始重打包",
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun copyText(context: Context, text: String) {
    try {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("path", text))
        Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
    } catch (e: Throwable) {
        Toast.makeText(context, "复制失败: ${e.message}", Toast.LENGTH_SHORT).show()
    }
}

private fun fileUri(context: Context, file: File): Uri {
    return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
}

private fun openApk(context: Context, file: File) {
    try {
        if (!file.exists()) {
            Toast.makeText(context, "文件不存在", Toast.LENGTH_SHORT).show()
            return
        }
        val uri = fileUri(context, file)
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    } catch (e: Throwable) {
        Toast.makeText(context, "打开失败: ${e.message}", Toast.LENGTH_SHORT).show()
    }
}

private fun shareApk(context: Context, file: File) {
    try {
        if (!file.exists()) {
            Toast.makeText(context, "文件不存在", Toast.LENGTH_SHORT).show()
            return
        }
        val uri = fileUri(context, file)
        val intent = Intent(Intent.ACTION_SEND)
            .setType("application/vnd.android.package-archive")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        context.startActivity(Intent.createChooser(intent, "分享 APK"))
    } catch (e: Throwable) {
        Toast.makeText(context, "分享失败: ${e.message}", Toast.LENGTH_SHORT).show()
    }
}

private fun openFolder(context: Context, dir: File) {
    try {
        if (!dir.exists() || !dir.isDirectory) {
            Toast.makeText(context, "目录不存在", Toast.LENGTH_SHORT).show()
            return
        }
        val uri = fileUri(context, dir)
        val intent = Intent(Intent.ACTION_VIEW)
            .setDataAndType(uri, "resource/folder")
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    } catch (e: Throwable) {
        Toast.makeText(context, "无法打开目录，已复制路径", Toast.LENGTH_SHORT).show()
        copyText(context, dir.absolutePath)
    }
}

// ==================== Log Tab ====================

@Composable
fun LogTab(logs: List<String>) {
    if (logs.isEmpty()) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("暂无日志", color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    } else {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(8.dp)
        ) {
            items(logs) { log ->
                val color = when {
                    log.contains("[ERROR]") || log.contains("[FATAL]") ->
                        MaterialTheme.colorScheme.error
                    log.contains("[DONE]") -> SuccessGreen
                    else -> MaterialTheme.colorScheme.onSurface
                }
                Text(
                    text = log,
                    style = MaterialTheme.typography.bodySmall,
                    color = color,
                    modifier = Modifier.padding(vertical = 2.dp),
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                )
            }
        }
    }
}
