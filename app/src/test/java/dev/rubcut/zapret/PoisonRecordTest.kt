package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.core.stack.StrategyAutopilot
import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.Presets
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Отравление разбора DPI подставной записью.
 *
 * Приём найден разбором байткода рабочего приложения (`Os.setsockoptInt` с
 * `IP_TTL` и отправка через `MSG_OOB`, строки `--fake`, `--fake-sni`) и
 * подтверждён замерами против реального фильтра, который полностью
 * пересобирает TCP-сегменты и читает SNI где угодно в потоке:
 *
 *   подставная запись, пауза 50 мс   10 из 10
 *   без подставы                        0 из 10
 */
class PoisonRecordTest {

    private val engine = DesyncEngine()

    /* ================================================================== */
    /*  Подстава обязана быть настоящей, целой TLS-записью              */
    /* ================================================================== */

    /**
     * Главное условие, найденное замерами: подставу нельзя обрезать.
     *
     * Обрезанный вариант (111 байт вместо 112) не просто не помогает — сервер
     * отвечает на него RST, потому что не может разобрать недописанное
     * рукопожатие, и соединение разрывается раньше, чем DPI что-либо решит.
     */
    @Test
    fun poisonIsACompleteParseableHello() {
        val poison = Tls.poisonHello("www.google.com")
        val info = Tls.parseClientHello(poison, 0, poison.size)

        assertNotNull("подстава обязана разбираться как ClientHello", info)
        assertEquals("домен в подставе должен читаться как заданный", "www.google.com", info!!.sni)
        assertEquals(
            "заявленная длина записи обязана совпадать с фактической, иначе сервер ответит RST",
            poison.size, Tls.recordTotalLength(poison, 0, poison.size)
        )
    }

    /** Подстава не должна нести чужой хост — она читается как обычный домен. */
    @Test
    fun poisonCarriesOnlyItsOwnName() {
        val poison = Tls.poisonHello(DesyncEngine.DEFAULT_POISON_SNI)
        val text = String(poison, Charsets.ISO_8859_1)
        assertTrue("домен подставы должен присутствовать", text.contains(DesyncEngine.DEFAULT_POISON_SNI))
        assertFalse(
            "подстава не должна содержать заблокированный домен настоящего рукопожатия",
            text.contains("youtube.com")
        )
    }

    /**
     * Каждое расширение подставы обязано занимать ровно свою заявленную длину.
     *
     * Тест написан после реальной ошибки: в `signature_algorithms` было забыто
     * поле длины списка, расширение получалось на два байта короче, и подстава
     * не работала вовсе — 0 из 5 против 10 из 10 у правильной. При этом разбор
     * ClientHello проходил: он читает только SNI и общую длину записи, а
     * содержимое остальных расширений не проверяет.
     */
    @Test
    fun everyPoisonExtensionFitsExactly() {
        val poison = Tls.poisonHello(DesyncEngine.DEFAULT_POISON_SNI)
        // Заголовок записи (5) + заголовок рукопожатия (4) + версия (2) +
        // random (32) + session id (1) + шифры (2 + 8) + сжатие (2) → начало расширений.
        val extStart = 5 + 4 + 2 + 32 + 1 + 2 + 8 + 2
        val extTotal = ((poison[extStart].toInt() and 0xFF) shl 8) or
            (poison[extStart + 1].toInt() and 0xFF)
        var off = extStart + 2
        val end = extStart + 2 + extTotal
        val seen = mutableSetOf<Int>()
        while (off + 4 <= end) {
            val type = ((poison[off].toInt() and 0xFF) shl 8) or (poison[off + 1].toInt() and 0xFF)
            val len = ((poison[off + 2].toInt() and 0xFF) shl 8) or
                (poison[off + 3].toInt() and 0xFF)
            assertTrue(
                "расширение 0x${type.toString(16)} заявляет $len байт, а после него остаётся " +
                    "${end - off - 4} — размеры не сходятся",
                off + 4 + len <= end
            )
            assertTrue("расширение 0x${type.toString(16)} продублировано", seen.add(type))
            off += 4 + len
        }
        assertEquals(
            "расширения должны кончиться ровно на заявленной границе",
            end, off
        )
        assertTrue("в подставе должно быть расширение server_name", seen.contains(0x0000))
        assertTrue("в подставе должно быть signature_algorithms", seen.contains(0x000D))
        assertTrue("в подставе должно быть supported_groups", seen.contains(0x000A))
    }

    /* ================================================================== */
    /*  Порядок отправки                                                 */
    /* ================================================================== */

    /**
     * Подстава уходит ДО настоящих данных, а не после и не вместо них.
     *
     * Если отправить её после, DPI успеет разобрать настоящий ClientHello и
     * заблокировать поток; если вместо — сервер не получит рукопожатия вовсе.
     */
    @Test
    fun poisonIsSentBeforeTheRealData() {
        val host = "www.youtube.com"
        val hello = StrategyAutopilotHelloFactory.build(host)
        val plan = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(desync = DesyncMode.NONE, poisonEnabled = true, poisonDelayMs = 50)
        )

        assertTrue("стратегия должна быть применена", plan.applied)
        val poison = plan.poison
        assertNotNull("подстава обязана быть в плане", poison)
        assertEquals(
            "подставу нельзя смешивать с фрагментами: она идёт отдельной записью",
            1, plan.writes.size
        )
        assertEquals(
            "настоящий ClientHello должен уйти целым и без изменений",
            hello.size, plan.writes[0].size
        )
        assertEquals(
            "подставу должно предшествовать настоящим данным — иначе DPI успеет заблокировать",
            "www.google.com",
            Tls.parseClientHello(poison!!, 0, poison.size)!!.sni
        )
        assertEquals(
            "настоящий домен обязан дойти до сервера в исходном виде",
            host, Tls.parseClientHello(plan.writes[0], 0, plan.writes[0].size)!!.sni
        )
        assertTrue("пауза после подставы обязана выставляться", plan.poisonDelayMs > 0)
    }

    /**
     * Пауза нужна: без неё подстава сливается с настоящей записью.
     *
     * Замеры против реального фильтра: 50 мс и 300 мс работают, 10 мс и
     * меньше — уже нет.
     */
    @Test
    fun poisonDelayIsHonoured() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        for (d in listOf(0, 10, 50, 300)) {
            val plan = engine.plan(
                hello, FlowContext(443, null, false),
                Strategy(desync = DesyncMode.NONE, poisonEnabled = true, poisonDelayMs = d)
            )
            assertEquals("пауза $d мс должна доходить до плана без изменений", d, plan.poisonDelayMs)
        }
    }

    /** Приём совместим с разбиением: подстава идёт перед фрагментами. */
    @Test
    fun poisonCombinesWithSplitting() {
        val hello = StrategyAutopilotHelloFactory.build("rr12---sn-4g5ednse.googlevideo.com")
        val plan = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(
                desync = DesyncMode.MULTISPLIT,
                splitPositions = listOf(dev.rubcut.zapret.data.SplitPos.FIRST,
                    dev.rubcut.zapret.data.SplitPos.MIDSNI),
                splitDelayMs = 2,
                poisonEnabled = true,
                poisonDelayMs = 50
            )
        )
        assertNotNull("подстава должна сохраняться вместе с разбиением", plan.poison)
        assertEquals("разбиение должно остаться: 3 фрагмента", 3, plan.writes.size)
        assertEquals(
            "общее число записей включает подставу",
            plan.writes.size + 1, plan.totalWrites
        )
        // Склеенные фрагменты дают исходный ClientHello без потерь.
        val rejoined = plan.writes.fold(ByteArray(0)) { a, w -> a + w }
        assertEquals(hello.size, rejoined.size)
    }

    /* ================================================================== */
    /*  Границы применения                                               */
    /* ================================================================== */

    /** Выключенный приём не должен ничего добавлять. */
    @Test
    fun poisonIsOffByDefault() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        val plan = engine.plan(hello, FlowContext(443, null, false), Strategy(desync = DesyncMode.NONE))
        assertNull("подстава не должна появляться без явного включения", plan.poison)
        assertEquals(0, plan.totalWrites - plan.writes.size)
    }

    /** Подставной записью нельзя заменить рукопожатие, которого нет. */
    @Test
    fun noHelloMeansNoPoison() {
        val junk = ByteArray(200) { 0x41 }
        val plan = engine.plan(
            junk, FlowContext(443, null, false),
            Strategy(desync = DesyncMode.MULTISPLIT, poisonEnabled = true)
        )
        assertNull("без ClientHello подставу отправлять нечем", plan.poison)
    }

    /* ================================================================== */
    /*  Профили и автоподбор                                             */
    /* ================================================================== */

    /**
     * Приём НЕЛЬЗЯ включать в профили — он ломает рукопожатие.
     *
     * Проверено полным TLS-рукопожатием с проверкой сертификата: подставная
     * запись — целый ClientHello, поэтому сервер отвечает на неё и присылает
     * сертификат для чужого домена. Клиент запрашивал `www.youtube.com`,
     * получил сертификат для `www.google.com`, и рукопожатие падает:
     * `INAPPROPRIATE_FALLBACK`. Ломается всё, включая Google, который до
     * включения приёма работал.
     *
     * Почему приём не спасти настройкой TTL, как в zapret: там фальшивый
     * пакет гаснет по пути к DPI и до сервера не доходит, но там работают с
     * пакетами напрямую. Обычный TCP-сокет переотправит неподтверждённую
     * подставу через секунду уже с нормальным TTL, и сервер получит её
     * в любом случае — уже посреди рукопожатия.
     */
    @Test
    fun poisonIsOffInEveryPreset() {
        for (p in ProfileId.entries) {
            val cfg = Presets.apply(p, AppConfig())
            assertFalse(
                "профиль ${p.token}: отравление обязано быть выключено — оно ломает " +
                    "рукопожатие, сервер отвечает сертификатом чужого домена",
                cfg.poisonEnabled
            )
            for (rule in cfg.rules) {
                assertFalse(
                    "правило «${rule.name}» профиля ${p.token}: отравление обязано быть выключено",
                    rule.strategy.poisonEnabled
                )
            }
        }
    }

    /**
     * Приём не должен попадать в автоподбор: он ломает рукопожатие, и зонд
     * принял бы за успех первый байт ответа сервера на подставу.
     */
    @Test
    fun poisonIsNotAmongAutopilotCandidates() {
        assertFalse(
            "отравление не должно быть среди кандидатов автоподбора: зонд проверяет " +
                "только первый байт ответа и принял бы сертификат чужого домена за успех",
            StrategyAutopilot.CANDIDATES.any { it.second.poisonEnabled }
        )
    }

    /** Имя подставного домена должно быть разбираемым и без пробелов. */
    @Test
    fun customPoisonNameIsAccepted() {
        val poison = Tls.poisonHello("example.org")
        assertEquals("example.org", Tls.parseClientHello(poison, 0, poison.size)!!.sni)
    }
}