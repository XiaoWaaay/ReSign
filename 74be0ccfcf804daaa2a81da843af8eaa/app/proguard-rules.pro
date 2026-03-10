# ReSignPro ProGuard Rules

-keep class com.xiao.resign.killsig.** { *; }
-keep class com.xiao.resign.killsig.SignatureKillerProvider { *; }

-keepclasseswithmembernames class * {
    native <methods>;
}

-keep class android.content.pm.PackageInfo { *; }
-keep class android.content.pm.Signature { *; }
-keep class android.content.pm.SigningInfo { *; }
-keep class android.app.ActivityThread { *; }
-keep class android.app.ApplicationPackageManager { *; }
