package dev.rubcut.zapret

import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.ProbeStatus
import dev.rubcut.zapret.data.ProfileId
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Список приёмов со значками «работает / не работает».
 *
 * Главное здесь — переживание перезапуска. Значки живут в конфиге, потому что
 * иначе после перезапуска приложения весь список снова выглядит непроверенным,
 * хотя подбор уже был выполнен и рабочий приём известен.
 */
class CandidateStatusTest {

    /** Статусы обязаны пережить сериализацию в JSON. */
    @Test
    fun statusesSurviveJsonRoundTrip() {
        val cfg = AppConfig(
            profile = ProfileId.CUSTOM,
            candidateStatus = mapOf(
                "disorder · середина домена (0+wm)" to ProbeStatus.WORKS,
                "multisplit · первый байт" to ProbeStatus.FAILS,
            ),
            candidateCheckedAt = 1_700_000_000_000L
        )
        val json = JSONObject(cfg.toJson().toString())
        val back = AppConfig.fromJson(json)

        assertEquals(
            "работающий приём обязан сохраниться",
            ProbeStatus.WORKS,
            back.candidateStatus["disorder · середина домена (0+wm)"]
        )
        assertEquals(
            "неработающий приём обязан сохраниться",
            ProbeStatus.FAILS,
            back.candidateStatus["multisplit · первый байт"]
        )
        assertEquals("время проверки обязано сохраниться", 1_700_000_000_000L, back.candidateCheckedAt)
    }

    /** Старый конфиг без этих полей обязан читаться без падения. */
    @Test
    fun missingFieldsAreTolerated() {
        val old = JSONObject(AppConfig().toJson().toString()).apply {
            remove("candidateStatus")
            remove("candidateCheckedAt")
        }
        val back = AppConfig.fromJson(old)
        assertTrue("статусы по умолчанию пусты", back.candidateStatus.isEmpty())
        assertEquals("время по умолчанию 0", 0L, back.candidateCheckedAt)
    }

    /** Неизвестный токен обязан трактоваться как «не проверен», а не падать. */
    @Test
    fun unknownTokenBecomesUnknown() {
        assertEquals(ProbeStatus.UNKNOWN, ProbeStatus.fromToken("какая-то дичь"))
        assertEquals(ProbeStatus.UNKNOWN, ProbeStatus.fromToken(null))
        assertEquals(ProbeStatus.WORKS, ProbeStatus.fromToken("WORKS"))
    }

    /**
     * Имена в списке и ключи статусов обязаны совпадать.
     *
     * Подбор ключу даёт имя без суффикса адреса (`name.substringBefore(" [")`),
     * а список строится по CANDIDATES. Расхождение означало бы, что значок
     * никогда не загорится: ключ есть, а искомого имени в списке нет.
     */
    @Test
    fun everyCandidateHasStableNameForStatus() {
        val names = StrategyAutopilot.CANDIDATES.map { it.first }
        assertTrue("список приёмов не должен быть пустым", names.isNotEmpty())
        assertEquals(
            "имена кандидатов обязаны быть уникальны: иначе статусы схлопнутся",
            names.size, names.toSet().size
        )
        for (n in names) {
            assertEquals(
                "имя «$n» обязано совпадать само с собой после отброса суффикса адреса",
                n, n.substringBefore(" [")
            )
        }
    }

    /** Три состояния обязаны быть различимы: «не проверен» ≠ «не работает». */
    @Test
    fun unknownAndFailsAreDistinct() {
        assertFalse(ProbeStatus.UNKNOWN == ProbeStatus.FAILS)
        assertEquals(3, ProbeStatus.values().size)
    }
}