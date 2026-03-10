package com.xiao.resign;

import android.os.Bundle;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

/**
 * MainActivity — 签名校验测试界面
 *
 * 加载 native-lib.so，其 JNI_OnLoad 会通过 getApplication() 获取签名并校验。
 * 如果 SignatureKiller 工作正常，即使 APK 被重签名，
 * native 层也会拿到原始签名 → 校验通过 → 显示 "signature is valid"
 */
public class MainActivity extends AppCompatActivity {

    static {
        System.loadLibrary("native-lib");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView tv = findViewById(R.id.sample_text);
        tv.setText(stringFromJNI());

        // 显示 SignatureKiller 状态
        TextView tvStatus = findViewById(R.id.tv_killer_status);
        if (tvStatus != null) {
            StringBuilder sb = new StringBuilder();
            sb.append("=== SignatureKiller Status ===\n");

            try {
                boolean installed = com.xiao.resign.killsig.SignatureKiller.isInstalled();
                sb.append("Java Hook: ").append(installed ? "ACTIVE ✓" : "INACTIVE ✗").append("\n");
            } catch (Exception e) {
                sb.append("Java Hook: ERROR (").append(e.getMessage()).append(")\n");
            }

            try {
                boolean nativeActive = com.xiao.resign.killsig.NativeSignatureKiller.nativeIsActive();
                sb.append("Native Hook: ").append(nativeActive ? "ACTIVE ✓" : "INACTIVE ✗").append("\n");
            } catch (Exception e) {
                sb.append("Native Hook: NOT LOADED\n");
            }

            tvStatus.setText(sb.toString());
        }
    }

    public native String stringFromJNI();
}
