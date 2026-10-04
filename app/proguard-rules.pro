-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# VpnService / TileService / Receiver создаются системой по имени класса.
-keep class dev.rubcut.zapret.vpn.ZapretVpnService { *; }
-keep class dev.rubcut.zapret.service.ZapretTileService { *; }
-keep class dev.rubcut.zapret.service.BootReceiver { *; }
-keep class dev.rubcut.zapret.ZapretApplication { *; }

# Compose
-dontwarn androidx.compose.**

# Освобождение памяти в нативных вызовах не используется, но на всякий случай:
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}
