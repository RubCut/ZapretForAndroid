package dev.rubcut.zapret

import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.vpn.effectiveMtuConfig
import dev.rubcut.zapret.vpn.tunnelSignatureOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Отпечаток конфига обязан совпадать у подъёма и у наблюдателя.
 *
 * Полевой баг: физическая сеть давала MTU 1430, в настройках стоял 1500.
 * `establish()` перед подъёмом ужимал MTU под сеть и сохранял отпечаток от
 * ужатого конфига (1430), а наблюдатель сравнивал её с сырым конфигом из
 * репозитория (1500). Первый же эмит выглядел как «параметры изменились»:
 * туннель перезапускался каждые ~350 мс, стеки TCP/DNS пересоздавались, и ни
 * одно соединение — включая зонды автоподбора — не успевало состояться.
 */
class MtuSignatureLoopTest {

    @Test
    fun cachedSignatureMatchesWatcherComparisonOnCappedMtu() {
        val raw = AppConfig(mtu = 1500)
        val cap = 1430

        // Так отпечаток сохраняется в establish() после ужатия MTU.
        val stored = tunnelSignatureOf(effectiveMtuConfig(raw, cap))

        // Наблюдатель обязан получить ровно ту же строку — иначе сразу рестарт.
        val watcherSees = tunnelSignatureOf(effectiveMtuConfig(raw, cap))
        assertEquals(
            "наблюдатель не должен видеть «изменение» сразу после подъёма туннеля",
            stored, watcherSees
        )

        // Старое (сломанное) сравнение — отпечаток ужатого конфига против
        // сырого — обязано отличаться: если это перестанет быть так, тест
        // больше не ловит регрессию.
        assertNotEquals(
            "сырой MTU 1500 не совпадает с сохранённым 1430 — именно это давало цикл",
            stored, tunnelSignatureOf(raw)
        )
    }

    @Test
    fun realMtuChangeBelowPhysicalCapStillForcesRestart() {
        val stored = tunnelSignatureOf(effectiveMtuConfig(AppConfig(mtu = 1500), 1430))
        val lowered = tunnelSignatureOf(effectiveMtuConfig(AppConfig(mtu = 1000), 1430))
        assertNotEquals(
            "ручное понижение MTU ниже физического обязано перезапустить туннель",
            stored, lowered
        )
    }

    @Test
    fun raisingMtuAboveCapKeepsSignatureStable() {
        val stored = tunnelSignatureOf(effectiveMtuConfig(AppConfig(mtu = 1500), 1430))
        val raised = tunnelSignatureOf(effectiveMtuConfig(AppConfig(mtu = 4000), 1430))
        assertEquals(
            "поднятие MTU выше физического предела не меняет эффективный MTU — рестарт не нужен",
            stored, raised
        )
    }
}
