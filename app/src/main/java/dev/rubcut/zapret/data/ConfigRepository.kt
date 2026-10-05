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

    /** Синхронный снимок — его читают потоки туннеля. */
    val current: AppConfig get() = cached

    val config: StateFlow<AppConfig> = context.zapretDataStore.data
        .map { prefs: Preferences -> decode(prefs[CONFIG_KEY]) }
        .catch { emit(factory()) }
        .onEach { cached = it }
        .stateIn(scope, SharingStarted.Eagerly, factory())

    suspend fun ensureLoaded() {
        val prefs = context.zapretDataStore.data.first()
        cached = decode(prefs[CONFIG_KEY])
    }

    suspend fun update(transform: (AppConfig) -> AppConfig) {
        val next = transform(cached)
        write(next)
    }

    suspend fun set(value: AppConfig) = write(value)

    /** Сброс к заводским значениям — это тоже профиль по умолчанию. */
    suspend fun reset() = write(factory())

    fun exportJson(): String = cached.toJson().toString(2)

    suspend fun importJson(json: String): Boolean {
        val parsed = runCatching { AppConfig.fromJson(JSONObject(json)) }.getOrNull() ?: return false
        write(parsed)
        return true
    }

    private suspend fun write(value: AppConfig) {
        context.zapretDataStore.edit { prefs -> prefs[CONFIG_KEY] = value.toJson().toString() }
        cached = value
    }

    private fun decode(raw: String?): AppConfig =
        if (raw.isNullOrBlank()) factory()
        else runCatching { AppConfig.fromJson(JSONObject(raw)) }.getOrElse { factory() }

    private companion object {
        val CONFIG_KEY: Preferences.Key<String> = stringPreferencesKey("config_json")
    }
}
