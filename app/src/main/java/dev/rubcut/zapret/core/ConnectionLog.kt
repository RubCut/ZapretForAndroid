package dev.rubcut.zapret.core

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.ConcurrentLinkedDeque

/** Короткая запись о соединении для экрана «Последние соединения». */
data class RecentConnection(
    val host: String,
    val address: String,
    val port: Int,
    val technique: String?,
    val applied: Boolean,
    val v6: Boolean,
    val at: Long
)

/** Глобальный список последних соединений — доступен и туннелю, и UI. */
object ConnectionLog {

    private const val MAX = 50
    private val deque = ConcurrentLinkedDeque<RecentConnection>()

    private val _entries = MutableStateFlow<List<RecentConnection>>(emptyList())
    val entries: StateFlow<List<RecentConnection>> = _entries

    fun add(entry: RecentConnection) {
        deque.addFirst(entry)
        while (deque.size > MAX) deque.pollLast()
        _entries.value = deque.toList()
    }

    fun clear() {
        deque.clear()
        _entries.value = emptyList()
    }
}
