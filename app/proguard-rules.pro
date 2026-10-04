-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# VpnService / TileService / Receiver создаются системой по имени класса.
-keep class dev.rubcut.zapret.vpn.ZapretVpnService { *; }
-keep class dev.rubcut.zapret.service.ZapretTileService { *; }
-keep class dev.rubcut.zapret.service.BootReceiver { *; }
-keep class dev.rubcut.zapret.ZapretApplication { *; }

# Activity тоже запускается системой (launcher + PendingIntent из уведомления),
# хотя манифест и уберегает её сам — правило не лишнее, а подстраховка.
-keep class dev.rubcut.zapret.ui.MainActivity { *; }

# Ресурсы: имена читаются только через R, но при R8 + shrinkResources
# удаление ресурсов иногда цепляет то, что ищется рефлексией.
-keepclassmembers class * extends android.content.Context {
    public void <init>(android.content.Context);
}

# Compose
-dontwarn androidx.compose.**

# Освобождение памяти в нативных вызовах не используется, но на всякий случай:
-keepclassmembers class * implements android.os.Parcelable {
    public static final ** CREATOR;
}
