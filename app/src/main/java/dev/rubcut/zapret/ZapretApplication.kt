package dev.rubcut.zapret

import android.app.Application
import android.content.Context
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.dns.AppContextProvider
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.ConfigRepository
import dev.rubcut.zapret.data.HostListStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Простой сервис-локатор: компоненты туннеля живут вне жизненного цикла Activity. */
object AppGraph {

    val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    lateinit var config: ConfigRepository
        private set
    lateinit var lists: HostListStore
        private set

    val configProvider: () -> AppConfig get() = { config.current }
    val listsProvider: () -> HostListStore.Snapshot get() = { lists.current }

    @Volatile
    var ready: Boolean = false
        private set

    fun init(context: Context) {
        if (ready) return
        val app = context.applicationContext
        AppContextProvider.init(app)
        lists = HostListStore(app)
        lists.loadBlocking()
        config = ConfigRepository(app, scope)
        ready = true
        scope.launch {
            config.config.collect { cfg ->
                LogManager.verbose = cfg.verboseLog
            }
        }
        LogManager.i(LogTag.APP, "Zapret инициализирован")
    }
}

class ZapretApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        AppGraph.init(this)
    }
}
