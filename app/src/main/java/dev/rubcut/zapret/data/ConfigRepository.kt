package dev.rubcut.zapret.data

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import android.util.Log
import dev.rubcut.zapret.data.DnsMode
import org.json.JSONObject

private val Context.zapretDataStore by preferencesDataStore(name = "zapret-config")

/**
 * Хранилище конфигурации. Весь [AppConfig] лежит одним JSON-документом: так проще
 * добавлять поля и переносить настройки между устройствами.
 */
class ConfigRepository(private val context: Context, scope: CoroutineScope) {

    /**
     * Заводская конфигурация — это профиль по умолчанию, а не пустой [AppConfig].
     *
     * Без этого первая установка показывала «профиль YouTube + Discord», но
     * работала на сырых значениях полей: без правил, без блокировки QUIC и без
     * разбиения по первому байту. Пользователь видел одно, а обход был другой.
     */
    private fun factory(): AppConfig = Presets.apply(ProfileId.COMBINED, AppConfig())

    @Volatile
    private var cached: AppConfig = factory()

    /** Мьютекс записи: убирает lost update при параллельных `update()` (слайдер + автоподбор). */
    private val writeMutex = Mutex()

    /**
     * Сырой JSON последней неудачной расшифровки.
     *
     * Битый документ больше не сносит конфиг молча: сырьё сохраняется в памяти
     * и дописывается в DataStore при следующей успешной записи (ключ
     * `config_json_corrupt`), чтобы настройки можно было восстановить вручную.
     */
    @Volatile
    var lastCorruptJson: String? = null
        private set

    /** Синхронный снимок — его читают потоки туннеля. */
    val current: AppConfig get() = cached

    val config: StateFlow<AppConfig> = context.zapretDataStore.data
        .map { prefs: Preferences -> decode(prefs[CONFIG_KEY]) }
        .onEach { cached = it }
        // Ошибка чтения диска (а не битого JSON) отдаёт последний известный
        // конфиг, а не заводской: раньше любой сбой DataStore сбрасывал UI
        // в COMBINED-пресет и затирал кэш через onEach ниже по цепочке.
        .catch { emit(cached) }
        .stateIn(scope, SharingStarted.Eagerly, factory())

    suspend fun ensureLoaded() {
        val prefs = context.zapretDataStore.data.first()
        writeMutex.withLock { cached = decode(prefs[CONFIG_KEY]) }
    }

    suspend fun update(transform: (AppConfig) -> AppConfig) {
        writeMutex.withLock { writeLocked(transform(cached)) }
    }

    suspend fun set(value: AppConfig) = writeMutex.withLock { writeLocked(value) }

    /** Сброс к заводским значениям — это тоже профиль по умолчанию. */
    suspend fun reset() = writeMutex.withLock { writeLocked(factory()) }

    fun exportJson(): String = cached.toJson().toString(2)

    suspend fun importJson(json: String): Boolean {
        val parsed = runCatching { AppConfig.fromJson(JSONObject(json)) }.getOrNull() ?: return false
        writeMutex.withLock { writeLocked(parsed) }
        return true
    }

    private suspend fun writeLocked(value: AppConfig) {
        // Миграция при каждой записи, а не только при чтении: импорт старого
        // JSON раньше навсегда застревал на старой схеме, потому что write()
        // сразу штамповал CURRENT_CONFIG_VERSION поверх устаревших правил.
        val migrated = migrateConfig(value)
        val stamped = migrated.copy(configVersion = CURRENT_CONFIG_VERSION)
        context.zapretDataStore.edit { prefs ->
            prefs[CONFIG_KEY] = stamped.toJson().toString()
            // Дописываем бэкап битого документа, если он был (см. decode).
            lastCorruptJson?.let { corrupt ->
                if (corrupt.length <= MAX_CORRUPT_BACKUP) prefs[CORRUPT_KEY] = corrupt
                lastCorruptJson = null
            }
        }
        cached = stamped
    }

    private fun decode(raw: String?): AppConfig {
        if (raw.isNullOrBlank()) return factory()
        val parsed = runCatching { AppConfig.fromJson(JSONObject(raw)) }.getOrElse { e ->
            Log.w(TAG, "битый config_json, откат к заводскому с бэкапом", e)
            lastCorruptJson = raw
            return factory()
        }
        return migrateConfig(parsed)
    }

    private companion object {
        val CONFIG_KEY: Preferences.Key<String> = stringPreferencesKey("config_json")
        val CORRUPT_KEY: Preferences.Key<String> = stringPreferencesKey("config_json_corrupt")
        const val TAG = "ConfigRepository"
        /** Бэкап битого JSON режем, чтобы не раздувать DataStore. */
        const val MAX_CORRUPT_BACKUP = 100 * 1024
    }
}

/**
 * Освежение конфигурации при смене схемы.
 *
 * Вне класса намеренно: репозиторию нужен Context, а чистая функция позволяет
 * проверить миграцию в обычном JVM-тесте.
 *
 * Про DNS: прежняя схема при сбое DoH НАВСЕГДА писала `dnsMode = SYSTEM`, и
 * режим застревал навсегда — имена резолвились через DNS провайдера, который
 * подменяет адреса (`example.com` приходил как `8.47.69.1`, и любая проверка
 * связи по такому адресу врала). Откат больше не трогает настройку, а вернуть
 * DoH нужно ровно один раз — здесь. Отличить добровольный выбор SYSTEM от
 * последствия бага нельзя, поэтому SYSTEM считаем следствием бага.
 */
internal fun migrateConfig(cfg: AppConfig): AppConfig {
    if (cfg.configVersion >= CURRENT_CONFIG_VERSION) return cfg
    val dns = if (cfg.dnsMode == DnsMode.SYSTEM) AppConfig().dnsMode else cfg.dnsMode
    if (cfg.profile == ProfileId.CUSTOM) {
        return cfg.copy(dnsMode = dns, configVersion = CURRENT_CONFIG_VERSION)
    }
    val fresh = Presets.apply(cfg.profile, AppConfig())
    val generated = cfg.rules.filter { it.isGenerated }
    return cfg.copy(
        rules = generated + fresh.rules,
        dnsMode = dns,
        configVersion = CURRENT_CONFIG_VERSION
    )
}
