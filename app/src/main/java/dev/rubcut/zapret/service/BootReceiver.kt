package dev.rubcut.zapret.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dev.rubcut.zapret.AppGraph
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.vpn.VpnController
import kotlinx.coroutines.launch

/**
 * Автозапуск туннеля после перезагрузки устройства или обновления приложения.
 *
 * Работает только если:
 *  1. в настройках включён «Автозапуск»;
 *  2. системное разрешение на VPN уже было выдано пользователем;
 *  3. Android не запрещает фоновый старт сервиса (на части версий OEM-прошивок
 *     это дополнительно ограничено оптимизацией батареи — см. чек-лист на
 *     главном экране).
 *
 * Всё завёрнуто в try/catch: неудачный автозапуск не должен ронять приёмник.
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED &&
            action != Intent.ACTION_MY_PACKAGE_REPLACED &&
            action != "android.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }

        try {
            AppGraph.init(context.applicationContext)
        } catch (e: Exception) {
            LogManager.w("Boot: не удалось инициализировать AppGraph: ${e.message}")
            return
        }

        val pending = goAsync()
        AppGraph.scope.launch {
            try {
                val cfg = AppGraph.config.current
                if (!cfg.autoStart) {
                    LogManager.d(LogTag.APP, "Boot: автозапуск выключен")
                    return@launch
                }
                if (VpnController.prepareIntent(context) != null) {
                    LogManager.i(LogTag.APP, "Boot: нет системного разрешения на VPN — пропуск")
                    return@launch
                }
                VpnController.startNow(context.applicationContext)
                LogManager.i(LogTag.APP, "Boot: туннель запускается автоматически")
            } catch (e: Exception) {
                LogManager.w("Boot: автозапуск не удался: ${e.message}")
            } finally {
                runCatching { pending.finish() }
            }
        }
    }
}
