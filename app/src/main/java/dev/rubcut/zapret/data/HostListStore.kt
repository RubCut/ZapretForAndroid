package dev.rubcut.zapret.data

import android.content.Context
import dev.rubcut.zapret.core.LogManager
import dev.rubcut.zapret.core.LogTag
import dev.rubcut.zapret.core.match.HostMatcher
import dev.rubcut.zapret.core.match.HostsTable
import dev.rubcut.zapret.core.match.IpMatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.withContext
import java.io.File

/**
 * Хранилище списков — аналог каталога `lists/` в zapret-discord-youtube.
 * Файлы лежат в `filesDir/lists`, в памяти держим готовые матчеры.
 */
class HostListStore(private val context: Context) {

    enum class Kind(val fileName: String) {
        HOSTLIST("hostlist.txt"),
        EXCLUDE("exclude.txt"),
        IPSET("ipset.txt"),
        IPSET_EXCLUDE("ipset-exclude.txt"),
        HOSTS("hosts.txt")
    }

    class Snapshot(
        val texts: Map<Kind, String>,
        val hostlist: HostMatcher,
        val exclude: HostMatcher,
        val ipset: IpMatcher,
        val ipsetExclude: IpMatcher,
        val hosts: HostsTable
    ) {
        fun count(kind: Kind): Int = when (kind) {
            Kind.HOSTLIST -> hostlist.size
            Kind.EXCLUDE -> exclude.size
            Kind.IPSET -> ipset.size
            Kind.IPSET_EXCLUDE -> ipsetExclude.size
            Kind.HOSTS -> hosts.size
        }

        companion object {
            val EMPTY = Snapshot(
                texts = emptyMap(),
                hostlist = HostMatcher.EMPTY,
                exclude = HostMatcher.EMPTY,
                ipset = IpMatcher.EMPTY,
                ipsetExclude = IpMatcher.EMPTY,
                hosts = HostsTable.EMPTY
            )
        }
    }

    private val dir: File get() = File(context.filesDir, "lists")

    private val _snapshot = MutableStateFlow(Snapshot.EMPTY)
    val snapshot: StateFlow<Snapshot> = _snapshot
    val current: Snapshot get() = _snapshot.value

    private val texts = HashMap<Kind, String>()

    /** Синхронная загрузка — вызывается один раз при старте процесса. */
    fun loadBlocking() {
        try {
            val d = dir
            if (!d.exists()) d.mkdirs()
            for (kind in Kind.values()) {
                val f = File(d, kind.fileName)
                val text = if (f.exists()) f.readText() else defaultFor(kind)
                if (!f.exists()) f.writeText(text)
                texts[kind] = text
            }
            rebuild()
        } catch (e: Exception) {
            LogManager.e("Не удалось загрузить списки", e)
        }
    }

    suspend fun save(kind: Kind, text: String) = withContext(Dispatchers.IO) {
        try {
            val d = dir
            if (!d.exists()) d.mkdirs()
            File(d, kind.fileName).writeText(text)
            texts[kind] = text
            rebuild()
            LogManager.i(LogTag.APP, "Список ${kind.fileName} сохранён (${text.lines().count { it.isNotBlank() }} строк)")
        } catch (e: Exception) {
            LogManager.e("Ошибка сохранения списка ${kind.fileName}", e)
        }
    }

    suspend fun appendLines(kind: Kind, lines: List<String>) {
        val currentText = texts[kind] ?: defaultFor(kind)
        val merged = LinkedHashSet<String>()
        currentText.lineSequence().forEach { merged += it }
        lines.forEach { merged += it.trim() }
        save(kind, merged.joinToString("\n"))
    }

    suspend fun resetToBuiltin() {
        for (kind in Kind.values()) save(kind, defaultFor(kind))
    }

    fun textOf(kind: Kind): String = texts[kind] ?: defaultFor(kind)

    private fun defaultFor(kind: Kind): String = when (kind) {
        Kind.HOSTLIST -> BuiltinLists.HOSTLIST_DEFAULT
        Kind.EXCLUDE -> BuiltinLists.EXCLUDE_EXAMPLE
        Kind.IPSET -> BuiltinLists.IPSET_ALL
        Kind.IPSET_EXCLUDE -> BuiltinLists.IPSET_EXCLUDE_EXAMPLE
        Kind.HOSTS -> BuiltinLists.HOSTS_EXAMPLE
    }

    private fun rebuild() {
        _snapshot.value = Snapshot(
            texts = texts.toMap(),
            hostlist = HostMatcher.parse(texts[Kind.HOSTLIST]),
            exclude = HostMatcher.parse(texts[Kind.EXCLUDE]),
            ipset = IpMatcher.parse(texts[Kind.IPSET]),
            ipsetExclude = IpMatcher.parse(texts[Kind.IPSET_EXCLUDE]),
            hosts = HostsTable.parse(texts[Kind.HOSTS])
        )
    }

    companion object {
        val GOOGLE_MATCHER: HostMatcher = HostMatcher.parse(BuiltinLists.GOOGLE)
        val DISCORD_MATCHER: HostMatcher = HostMatcher.parse(BuiltinLists.DISCORD)
        val GENERAL_MATCHER: HostMatcher = HostMatcher.parse(BuiltinLists.GENERAL)
        val ADS_MATCHER: HostMatcher = HostMatcher.parse(BuiltinLists.ADS_BLOCK)
    }
}
