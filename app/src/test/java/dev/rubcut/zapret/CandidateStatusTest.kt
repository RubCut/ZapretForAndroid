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
 * Список приёмов со значками «работает / не работает», отдельно по хостам.
 *
 * Главное здесь — переживание перезапуска и честность группировки. Значки
 * живут в конфиге, потому что иначе после перезапуска приложения весь список
 * снова выглядит непроверенным, хотя подбор уже был выполнен. А группировка
 * по хостам обязательна, потому что хосты блокируются по-разному: один и тот
 * же приём на YouTube работает, а на Discord — нет.
 */
class CandidateStatusTest {

    /** Статусы обязаны пережить сериализацию в JSON, отдельно по хостам. */
    @Test
    fun statusesSurviveJsonRoundTrip() {
        val cfg = AppConfig(
            profile = ProfileId.CUSTOM,
            candidateStatus = mapOf(
                "www.youtube.com" to mapOf(
                    "disorder · середина домена (0+wm)" to ProbeStatus.WORKS,
                    "multisplit · первый байт" to ProbeStatus.FAILS,
                ),
                "discord.com" to mapOf(
                    "disorder · середина домена (0+wm)" to ProbeStatus.FAILS,
                ),
            ),
            candidateCheckedAt = mapOf(
                "www.youtube.com" to 1_700_000_000_000L,
                "discord.com" to 1_700_000_001_000L,
            )
        )
        val json = JSONObject(cfg.toJson().toString())
        val back = AppConfig.fromJson(json)

        assertEquals(
            "работающий приём на YouTube обязан сохраниться",
            ProbeStatus.WORKS,
            back.candidateStatus["www.youtube.com"]?.get("disorder · середина домена (0+wm)")
        )
        assertEquals(
            "тот же приём на Discord обязан остаться нерабочим, а не заразиться",
            ProbeStatus.FAILS,
            back.candidateStatus["discord.com"]?.get("disorder · середина домена (0+wm)")
        )
        assertEquals(
            "время проверки YouTube обязано сохраниться",
            1_700_000_000_000L, back.candidateCheckedAt["www.youtube.com"]
        )
        assertEquals(
            "время проверки Discord обязано сохраниться",
            1_700_000_001_000L, back.candidateCheckedAt["discord.com"]
        )
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
        assertTrue("время по умолчанию пусто", back.candidateCheckedAt.isEmpty())
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