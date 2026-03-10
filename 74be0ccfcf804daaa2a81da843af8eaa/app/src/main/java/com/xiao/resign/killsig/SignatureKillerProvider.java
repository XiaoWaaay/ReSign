package com.xiao.resign.killsig;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.util.Log;

/**
 * SignatureKillerProvider — 签名 Hook 的最早初始化入口
 *
 * 初始化时序：
 * 1. Application.attachBaseContext()
 * 2. ContentProvider.onCreate()  ← 我们在这里
 * 3. Application.onCreate()
 * 4. Activity.onCreate()
 *    → System.loadLibrary("native-lib") 在 static{} 中
 *    → JNI_OnLoad 执行签名校验
 *
 * 但注意：如果 native-lib 在 Application.onCreate() 中加载，
 * 那 ContentProvider.onCreate() 足够早。
 * 如果在 Application.attachBaseContext() 中加载，则需要额外处理。
 *
 * 对于当前项目：
 * native-lib 在 MainActivity.static{} 中加载，
 * 即 Activity.onCreate() 时才加载 → ContentProvider.onCreate() 时机足够早。
 */
public class SignatureKillerProvider extends ContentProvider {

    private static final String TAG = "SigKillerProvider";

    @Override
    public boolean onCreate() {
        Context context = getContext();
        if (context == null) {
            Log.e(TAG, "Context is null!");
            return false;
        }

        Log.i(TAG, "=== SignatureKiller initializing ===");

        try {
            SignatureKiller.install(context);
            Log.i(TAG, "=== SignatureKiller V3 installed ===");
        } catch (Throwable t) {
            Log.e(TAG, "Install failed", t);
        }

        return true;
    }

    // ContentProvider 的其他方法返回空实现
    @Override
    public Cursor query(Uri uri, String[] projection, String selection,
                        String[] selectionArgs, String sortOrder) { return null; }
    @Override
    public String getType(Uri uri) { return null; }
    @Override
    public Uri insert(Uri uri, ContentValues values) { return null; }
    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) { return 0; }
    @Override
    public int update(Uri uri, ContentValues values, String selection,
                      String[] selectionArgs) { return 0; }
}
