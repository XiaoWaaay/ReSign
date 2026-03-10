# ReSignPro ProGuard Rules
-keep class com.resign.pro.native_bridge.** { *; }
-keep class com.resign.pro.core.** { *; }
-keep class top.canyie.pine.** { *; }
-dontwarn top.canyie.pine.**
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}
