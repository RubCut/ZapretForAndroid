package dev.rubcut.zapret.core

import android.os.SystemClock
import android.util.Log as AndroidLog
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

enum class LogTag(val label: String, val priority: Int) {
    APP("APP", AndroidLog.INFO),
    VPN("VPN", AndroidLog.INFO),
    TCP("TCP", AndroidLog.DEBUG),
    UDP("UDP", AndroidLog.DEBUG),
    DNS("DNS", AndroidLog.DEBUG),
    DPI("DPI", AndroidLog.INFO),
    WARN("WARN", AndroidLog.WARN),
    ERR("ERR", AndroidLog.ERROR)
}

data class LogEntry(
    val id: Long,
    val elapsed: Long,
    val tag: LogTag,
    val message: String,
    /** Настенное время записи — для отображения в журнале. */
    val time: Long = System.currentTimeMillis()
)

/**
 * Кольцевой журнал работы туннеля. Публикуется в UI не чаще [PUBLISH_INTERVAL_MS],
 * чтобы частые записи не дёргали recomposition.
 */
object LogManager {

    private const val MAX_ENTRIES = 1200
    private const val PUBLISH_INTERVAL_MS = 250L

    private val lock = Any()
    private val buffer = ArrayDeque<LogEntry>()
    private var nextId = 1L
    private var lastPublish = 0L

    private val _entries = MutableStateFlow<List<LogEntry>>(emptyList())
    val entries: StateFlow<List<LogEntry>> = _entries

    private val _counters = MutableStateFlow<Map<LogTag, Int>>(emptyMap())
    val counters: StateFlow<Map<LogTag, Int>> = _counters

    @Volatile
    var verbose: Boolean = false

    fun d(tag: LogTag, message: String) {
        if (!verbose && tag.priority == AndroidLog.DEBUG) return
        write(tag, message)
    }

    fun i(tag: LogTag, message: String) = write(tag, message)

    fun w(message: String, t: Throwable? = null) =
        write(LogTag.WARN, message + suffix(t))

    fun e(message: String, t: Throwable? = null) {
        write(LogTag.ERR, message + suffix(t))
        if (t != null) AndroidLog.e("Zapret", message, t)
    }

    private fun suffix(t: Throwable?): String =
        t?.let { " (${it.javaClass.simpleName}: ${it.message})" } ?: ""

    private fun write(tag: LogTag, message: String) {
        val entry = LogEntry(
            id = synchronized(lock) { nextId++ },
            elapsed = SystemClock.elapsedRealtime(),
            tag = tag,
            message = message
        )
        var publish: List<LogEntry> = emptyList()
        var counters: Map<LogTag, Int> = emptyMap()
        synchronized(lock) {
            buffer.addLast(entry)
            while (buffer.size > MAX_ENTRIES) buffer.removeFirst()
            val now = SystemClock.elapsedRealtime()
            if (now - lastPublish >= PUBLISH_INTERVAL_MS || tag == LogTag.ERR) {
                lastPublish = now
                publish = buffer.toList()
                counters = buffer.groupingBy { it.tag }.eachCount()
            }
        }
        if (publish.isNotEmpty()) {
            _entries.value = publish
            _counters.value = counters
        }
        AndroidLog.println(tag.priority, "Zapret/" + tag.label, message)
    }

    fun flushNow() {
        synchronized(lock) {
            _entries.value = buffer.toList()
            _counters.value = buffer.groupingBy { it.tag }.eachCount()
        }
    }

    fun clear() {
        synchronized(lock) {
            buffer.clear()
            _entries.value = emptyList()
            _counters.value = emptyMap()
        }
    }
}
