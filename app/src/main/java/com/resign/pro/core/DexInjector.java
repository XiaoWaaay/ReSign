package com.resign.pro.core;

import com.resign.pro.util.Logger;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.value.StringEncodedValue;
import org.jf.dexlib2.immutable.value.ImmutableStringEncodedValue;
import org.jf.dexlib2.rewriter.DexRewriter;
import org.jf.dexlib2.rewriter.EncodedValueRewriter;
import org.jf.dexlib2.rewriter.Rewriter;
import org.jf.dexlib2.rewriter.RewriterModule;
import org.jf.dexlib2.rewriter.Rewriters;
import org.jf.dexlib2.writer.io.FileDataStore;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * DEX注入器
 * 
 * 功能：
 * 1. 读取payload DEX模板
 * 2. 替换预设占位符字符串（包名、签名、原始入口类等）
 * 3. 输出填充后的DEX文件
 * 
 * 占位符定义（在HookEntry.java中声明为static final字段）：
 * - $$RESIGN_PKG$$         -> 目标包名
 * - $$RESIGN_SIG$$         -> 原始签名hex（多个用|分隔）
 * - $$RESIGN_APP_CLASS$$   -> 原始Application类名
 * - $$RESIGN_FACTORY$$     -> 原始AppComponentFactory类名
 * - $$RESIGN_JAVA_HOOK$$   -> "true"/"false"
 * - $$RESIGN_NATIVE_HOOK$$ -> "true"/"false"
 * - $$RESIGN_IO_REDIRECT$$ -> "true"/"false"
 * - $$RESIGN_MAPS_HIDE$$   -> "true"/"false"
 * - $$RESIGN_DEEP_HIDE$$   -> "true"/"false"
 * - $$RESIGN_DEBUG$$       -> "true"/"false"
 * - $$RESIGN_HOOK_MODE$$   -> "SAFE"/"STANDARD"/"AGGRESSIVE"
 * - $$RESIGN_NATIVE_BACKEND$$ -> "PLT"/"DOBBY"/"SECCOMP"/"HYBRID"
 */
public class DexInjector {

    private static final String TAG = "DexInjector";

    /**
     * Patch配置
     */
    public static class PatchConfig {
        public String packageName = "";
        public String signatureData = "";
        public String originalAppClass = "";
        public String originalFactoryClass = "";
        public boolean enableJavaHook = true;
        public boolean enableNativeHook = true;
        public boolean enableIoRedirect = true;
        public boolean enableMapsHide = true;
        public boolean enableDeepHide = true;
        public boolean debugLog = false;
        public String hookMode = "STANDARD";
        public String nativeBackend = "PLT";
    }

    /**
     * 对payload DEX进行占位符替换
     * 
     * @param templateDex 模板DEX文件（包含占位符）
     * @param outputDex   输出DEX文件
     * @param config      填充配置
     */
    public void patchPayloadDex(File templateDex, File outputDex, PatchConfig config) throws Exception {
        // 构建替换映射
        Map<String, String> replacements = new HashMap<>();
        replacements.put("$$RESIGN_PKG$$", config.packageName);
        replacements.put("$$RESIGN_SIG$$", config.signatureData);
        replacements.put("$$RESIGN_APP_CLASS$$", config.originalAppClass);
        replacements.put("$$RESIGN_FACTORY$$", config.originalFactoryClass);
        replacements.put("$$RESIGN_JAVA_HOOK$$", String.valueOf(config.enableJavaHook));
        replacements.put("$$RESIGN_NATIVE_HOOK$$", String.valueOf(config.enableNativeHook));
        replacements.put("$$RESIGN_IO_REDIRECT$$", String.valueOf(config.enableIoRedirect));
        replacements.put("$$RESIGN_MAPS_HIDE$$", String.valueOf(config.enableMapsHide));
        replacements.put("$$RESIGN_DEEP_HIDE$$", String.valueOf(config.enableDeepHide));
        replacements.put("$$RESIGN_DEBUG$$", String.valueOf(config.debugLog));
        replacements.put("$$RESIGN_HOOK_MODE$$", config.hookMode);
        replacements.put("$$RESIGN_NATIVE_BACKEND$$", config.nativeBackend);

        Logger.i(TAG, "开始Patch payload DEX, 替换项: " + replacements.size());
        for (Map.Entry<String, String> entry : replacements.entrySet()) {
            String val = entry.getValue();
            if (val.length() > 100) val = val.substring(0, 100) + "...";
            Logger.d(TAG, "  " + entry.getKey() + " -> " + val);
        }

        // 使用dexlib2进行字符串替换
        DexFile dexFile = DexFileFactory.loadDexFile(templateDex, Opcodes.forApi(34));

        DexRewriter rewriter = new DexRewriter(new RewriterModule() {
            @Override
            public Rewriter<org.jf.dexlib2.iface.value.EncodedValue> getEncodedValueRewriter(Rewriters rewriters) {
                return new EncodedValueRewriter(rewriters) {
                    @Override
                    public org.jf.dexlib2.iface.value.EncodedValue rewrite(org.jf.dexlib2.iface.value.EncodedValue value) {
                        if (value instanceof StringEncodedValue) {
                            String original = ((StringEncodedValue) value).getValue();
                            String replaced = applyReplacements(original, replacements);
                            if (!replaced.equals(original)) {
                                return new ImmutableStringEncodedValue(replaced);
                            }
                        }
                        return super.rewrite(value);
                    }
                };
            }

            @Override
            public Rewriter<String> getTypeRewriter(Rewriters rewriters) {
                return new Rewriter<String>() {
                    @Override
                    public String rewrite(String value) {
                        return value;
                    }
                };
            }
        });

        DexFile rewrittenDex = rewriter.getDexFileRewriter().rewrite(dexFile);

        // 写入输出文件
        org.jf.dexlib2.writer.pool.DexPool pool = new org.jf.dexlib2.writer.pool.DexPool(Opcodes.forApi(34));
        for (ClassDef classDef : rewrittenDex.getClasses()) {
            pool.internClass(classDef);
        }
        pool.writeTo(new FileDataStore(outputDex));

        Logger.i(TAG, "Payload DEX patch完成: " + outputDex.getAbsolutePath()
                + " (" + outputDex.length() + " bytes)");
    }

    /**
     * 应用字符串替换
     */
    private static String applyReplacements(String original, Map<String, String> replacements) {
        String result = original;
        for (Map.Entry<String, String> entry : replacements.entrySet()) {
            if (result.contains(entry.getKey())) {
                result = result.replace(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }
}
