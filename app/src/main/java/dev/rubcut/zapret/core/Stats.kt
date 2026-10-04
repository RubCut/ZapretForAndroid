package dev.rubcut.zapret.core

import android.os.SystemClock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.util.concurrent.atomic.AtomicLong

data class StatsSnapshot(
    val running: Boolean = false,
    val startedAt: Long = 0L,
    val bytesDown: Long = 0L,
    val bytesUp: Long = 0L,
    val packetsDown: Long = 0L,
    val packetsUp: Long = 0L,
    val activeConnections: Int = 0,
    val totalConnections: Long = 0L,
    val desyncedConnections: Long = 0L,
    val dnsQueries: Long = 0L,
    val blockedQuic: Long = 0L,
    val droppedPackets: Long = 0L
) {
    val uptimeMs: Long get() = if (startedAt == 0L) 0L else SystemClock.elapsedRealtime() - startedAt
}

/** Счётчики трафика туннеля. Живут в singleton, чтобы UI мог читать их без привязки к сервису. */
object TrafficStats {

    private val bytesDown = AtomicLong()
    private val bytesUp = AtomicLong()
    private val packetsDown = AtomicLong()
    private val packetsUp = AtomicLong()
    private val totalConnections = AtomicLong()
    private val desyncedConnections = AtomicLong()
    private val dnsQueries = AtomicLong()
    private val blockedQuic = AtomicLong()
    private val droppedPackets = AtomicLong()

    @Volatile
    var activeConnections: Int = 0

    private val _snapshot = MutableStateFlow(StatsSnapshot())
    val snapshot: StateFlow<StatsSnapshot> = _snapshot

    private var startedAt = 0L
    private var lastUiPush = 0L

    fun reset() {
        bytesDown.set(0); bytesUp.set(0)
        packetsDown.set(0); packetsUp.set(0)
        totalConnections.set(0); desyncedConnections.set(0)
        dnsQueries.set(0); blockedQuic.set(0); droppedPackets.set(0)
        activeConnections = 0
        startedAt = SystemClock.elapsedRealtime()
        publish(force = true)
    }

    fun stopped() {
        startedAt = 0L
        activeConnections = 0
        publish(force = true)
    }

    fun down(bytes: Int) { bytesDown.addAndGet(bytes.toLong()); packetsDown.incrementAndGet(); publish(false) }
    fun up(bytes: Int) { bytesUp.addAndGet(bytes.toLong()); packetsUp.incrementAndGet(); publish(false) }
    fun connectionOpened() { totalConnections.incrementAndGet(); activeConnections++; publish(false) }
    fun connectionClosed() { activeConnections = (activeConnections - 1).coerceAtLeast(0); publish(false) }
    fun desynced() { desyncedConnections.incrementAndGet(); publish(false) }
    fun dnsQueried() { dnsQueries.incrementAndGet(); publish(false) }
    fun quicBlocked() { blockedQuic.incrementAndGet(); droppedPackets.incrementAndGet(); publish(false) }
    fun dropped() { droppedPackets.incrementAndGet() }

    private fun publish(force: Boolean) {
        val now = SystemClock.elapsedRealtime()
        if (!force && now - lastUiPush < 700L) return
        lastUiPush = now
        _snapshot.value = StatsSnapshot(
            running = startedAt != 0L,
            startedAt = startedAt,
            bytesDown = bytesDown.get(),
            bytesUp = bytesUp.get(),
            packetsDown = packetsDown.get(),
            packetsUp = packetsUp.get(),
            activeConnections = activeConnections,
            totalConnections = totalConnections.get(),
            desyncedConnections = desyncedConnections.get(),
            dnsQueries = dnsQueries.get(),
            blockedQuic = blockedQuic.get(),
            droppedPackets = droppedPackets.get()
        )
    }
}

fun formatBytes(bytes: Long): String {
    if (bytes < 1024) return "$bytes B"
    val kb = bytes / 1024.0
    if (kb < 1024) return String.format(java.util.Locale.US, "%.1f KB", kb)
    val mb = kb / 1024.0
    if (mb < 1024) return String.format(java.util.Locale.US, "%.1f MB", mb)
    return String.format(java.util.Locale.US, "%.2f GB", mb / 1024.0)
}

fun formatUptime(ms: Long): String {
    val total = ms / 1000
    val h = total / 3600
    val m = (total % 3600) / 60
    val s = total % 60
    return String.format(java.util.Locale.US, "%d:%02d:%02d", h, m, s)
}
