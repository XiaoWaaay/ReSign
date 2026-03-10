/**
 * native-lib.cpp — 签名校验 Native 库
 *
 * 这个文件保持和原始 GitHub 项目一致的签名校验逻辑：
 * 1. JNI_OnLoad 时通过 ActivityThread.currentApplication() 拿到 Context
 * 2. 通过 PackageManager.getPackageInfo(GET_SIGNATURES) 获取签名
 * 3. 计算签名的 MD5（通过 Java MessageDigest）
 * 4. 与硬编码的 MD5 比较
 *
 * SignatureKiller 的拦截链路：
 * JNI_OnLoad → getApplication() → OK，返回 Application 对象
 * → getPackageManager() → 返回 ApplicationPackageManager（mPM 已被代理）
 * → getPackageInfo(pkgName, 64) → 走代理的 IPackageManager
 * → 代理拦截，将返回值中的 signatures 替换为原始签名
 * → signatureMd5() 计算出的是原始签名的 MD5
 * → 与 app_md5 比较 → MATCH
 */

#include <jni.h>
#include <string>
#include "android/log.h"

#define TAG "resign"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static int is_valid = 0;

// 原始签名的 MD5 值（重打包工具应该在编译时替换这个值）
static const char *app_md5 = "d2bac4b0c1e1e63c02bdb076e41c1e0b";

int verifySign(JNIEnv *env);
static jobject getApplication(JNIEnv *env);
char *signatureMd5(JNIEnv *env, jobject context);

// ==================== JNI 导出 ====================

extern "C"
JNIEXPORT jstring JNICALL
Java_com_xiao_resign_MainActivity_stringFromJNI(JNIEnv *env, jobject /* this */) {
    if (is_valid == 1) {
        return env->NewStringUTF("signature is valid");
    }
    return env->NewStringUTF("signature is not valid !!!");
}

extern "C"
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    if (vm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }

    LOGD("JNI_OnLoad: starting signature verification...");
    verifySign(env);
    LOGD("JNI_OnLoad: verification result = %d", is_valid);

    return JNI_VERSION_1_6;
}

// ==================== 签名校验 ====================

/**
 * 获取 Application Context
 *
 * 通过反射调用 ActivityThread.currentApplication()
 * 这是 native 层常用的获取 Context 方法
 */
static jobject getApplication(JNIEnv *env) {
    jclass localClass = env->FindClass("android/app/ActivityThread");
    if (localClass == NULL) {
        LOGE("Cannot find ActivityThread class");
        return NULL;
    }

    jmethodID currentApplicationId = env->GetStaticMethodID(
            localClass, "currentApplication", "()Landroid/app/Application;");
    if (currentApplicationId == NULL) {
        LOGE("Cannot find currentApplication method");
        return NULL;
    }

    jobject application = env->CallStaticObjectMethod(localClass, currentApplicationId);
    if (application == NULL) {
        LOGE("currentApplication() returned null");
    }
    return application;
}

/**
 * 获取签名 MD5
 *
 * 调用链：
 * context.getPackageManager() → ApplicationPackageManager (mPM 已被代理)
 * → pm.getPackageInfo(pkgName, 64) → 走代理的 IPackageManager
 * → PackageInfo.signatures → 已被替换为原始签名
 * → signature.toCharsString() → 签名字符串
 * → MessageDigest.getInstance("MD5").digest() → MD5 哈希
 */
char *signatureMd5(JNIEnv *env, jobject context) {
    // 获取 PackageManager
    jclass context_clz = env->GetObjectClass(context);
    jmethodID getPackageManager = env->GetMethodID(context_clz, "getPackageManager",
                                                   "()Landroid/content/pm/PackageManager;");
    jobject pm = env->CallObjectMethod(context, getPackageManager);

    // 获取包名
    jmethodID getPackageName = env->GetMethodID(context_clz, "getPackageName",
                                                "()Ljava/lang/String;");
    jstring packageName = static_cast<jstring>(env->CallObjectMethod(context, getPackageName));

    // 获取 PackageInfo (flag 64 = GET_SIGNATURES)
    jclass pm_clz = env->GetObjectClass(pm);
    jmethodID getPackageInfo = env->GetMethodID(pm_clz, "getPackageInfo",
                                                "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    jobject packageInfo = env->CallObjectMethod(pm, getPackageInfo, packageName, 64);

    if (packageInfo == NULL) {
        LOGE("getPackageInfo returned null");
        return strdup("error");
    }

    // 获取 signatures 数组
    jclass packageinfo_clz = env->GetObjectClass(packageInfo);
    jfieldID signaturesFid = env->GetFieldID(packageinfo_clz, "signatures",
                                             "[Landroid/content/pm/Signature;");
    jobjectArray signatures = (jobjectArray) env->GetObjectField(packageInfo, signaturesFid);

    if (signatures == NULL || env->GetArrayLength(signatures) == 0) {
        LOGE("No signatures found");
        return strdup("no_signatures");
    }

    // 获取第一个签名的字符串
    jobject signatureObj = env->GetObjectArrayElement(signatures, 0);
    jclass signature_clz = env->GetObjectClass(signatureObj);
    jmethodID toCharsString = env->GetMethodID(signature_clz, "toCharsString",
                                               "()Ljava/lang/String;");
    jstring signatureStr = (jstring) env->CallObjectMethod(signatureObj, toCharsString);

    const char *c_str = env->GetStringUTFChars(signatureStr, 0);

    // 使用 Java MessageDigest 计算 MD5
    jclass md_clz = env->FindClass("java/security/MessageDigest");
    jmethodID getInstance = env->GetStaticMethodID(md_clz, "getInstance",
                                                   "(Ljava/lang/String;)Ljava/security/MessageDigest;");
    jstring md5Str = env->NewStringUTF("MD5");
    jobject mdObj = env->CallStaticObjectMethod(md_clz, getInstance, md5Str);

    // 将签名字符串转为 byte[]
    jbyteArray inputBytes = env->NewByteArray(strlen(c_str));
    env->SetByteArrayRegion(inputBytes, 0, strlen(c_str), (jbyte *) c_str);

    // 调用 digest(byte[])
    jmethodID digest = env->GetMethodID(md_clz, "digest", "([B)[B");
    jbyteArray digestBytes = (jbyteArray) env->CallObjectMethod(mdObj, digest, inputBytes);

    // 转为十六进制字符串
    jsize digestLen = env->GetArrayLength(digestBytes);
    jbyte *digestData = env->GetByteArrayElements(digestBytes, NULL);

    char *result = (char *) malloc(digestLen * 2 + 1);
    for (int i = 0; i < digestLen; i++) {
        sprintf(result + i * 2, "%02x", (unsigned char) digestData[i]);
    }
    result[digestLen * 2] = '\0';

    env->ReleaseByteArrayElements(digestBytes, digestData, 0);
    env->ReleaseStringUTFChars(signatureStr, c_str);

    LOGD("Computed signature MD5: %s", result);
    return result;
}

/**
 * 执行签名校验
 */
int verifySign(JNIEnv *env) {
    jobject context = getApplication(env);
    if (context == NULL) {
        LOGE("Cannot get application context");
        return -1;
    }

    char *sign_md5 = signatureMd5(env, context);
    LOGD("signatureMd5: %s", sign_md5);
    LOGD("expected:     %s", app_md5);

    int ret = strcmp(sign_md5, app_md5);
    if (ret == 0) {
        is_valid = 1;
        LOGD("Signature verification PASSED!");
    } else {
        LOGD("Signature verification FAILED!");
    }

    free(sign_md5);
    return ret;
}
