package dev.rubcut.zapret

import dev.rubcut.zapret.core.desync.DesyncEngine
import dev.rubcut.zapret.core.desync.FlowContext
import dev.rubcut.zapret.core.net.getU16
import dev.rubcut.zapret.core.proto.Tls
import dev.rubcut.zapret.data.DesyncMode
import dev.rubcut.zapret.data.SplitPos
import dev.rubcut.zapret.data.Strategy
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `MULTISPLIT_TLSREC` обязан делать обе половины своего названия.
 *
 * Регрессия: ветка переупаковки записей возвращалась раньше общего кода и брала
 * только границы переупакованных записей. Точки из `splitPositions` игнорировались
 * полностью — то есть заявленная комбинация «TLS-записи + разбиение» на деле
 * была просто «TLS-записи».
 *
 * На реальном фильтре, судя по журналу стороннего приложения, именно эта
 * комбинация и была единственной рабочей для YouTube, поэтому поломка была не
 * косметической.
 */
class TlsrecWithSplitTest {

    private val engine = DesyncEngine()

    @Test
    fun tlsrecRepackAloneSplitsAtRecordBoundaries() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        // Дефолтные точки Strategy — [MIDSNI], поэтому рез идёт по точке,
        // а не пополам; фиксируем это явно, чтобы тест не зависел от дефолтов.
        val plain = Strategy(
            desync = DesyncMode.TLSREC,
            tlsrecParts = 2,
            splitPositions = listOf(SplitPos.MIDSNI)
        )
        val plan = engine.plan(hello, FlowContext(443, null, false), plain)

        assertTrue("переупаковка обязана применяться", plan.applied)
        assertTrue("ожидалось не меньше двух записей, получено ${plan.writes.size}", plan.writes.size >= 2)
        // Переупаковка вставляет один лишний заголовок записи: длина растёт
        // ровно на RECORD_HEADER, а не сохраняется.
        assertEquals(
            "переупаковка добавляет ровно один заголовок",
            hello.size + Tls.RECORD_HEADER, plan.writes.sumOf { it.size }
        )
    }

    /**
     * Ключевая проверка: разрыв из `splitPositions` обязан применяться ВМЕСТЕ с
     * переупаковкой, а не вместо неё.
     */
    @Test
    fun multisplitTlsrecAppliesBothHalves() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")

        val tlsrecOnly = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(
                desync = DesyncMode.TLSREC,
                tlsrecParts = 2,
                splitPositions = listOf(SplitPos.MIDSNI)
            )
        )
        val both = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(
                desync = DesyncMode.MULTISPLIT_TLSREC,
                tlsrecParts = 2,
                splitPositions = listOf(SplitPos.FIRST)
            )
        )

        assertTrue("multisplit+tlsrec обязан применять стратегию", both.applied)
        assertTrue(
            "разрыв по первому байту обязан добавить запись: было ${tlsrecOnly.writes.size}, " +
                "стало ${both.writes.size}",
            both.writes.size > tlsrecOnly.writes.size
        )
        assertEquals(
            "первая запись при разрыве по первому байту — ровно один байт",
            1, both.writes.first().size
        )
    }

    /**
     * Точный рез записи: граница обязана лежать там, где попросили, а тело —
     * собраться обратно байт в байт.
     *
     * Это ядро приёма `--tlsrec=0+wm --split=0+wm`. Если вторая часть
     * начнётся не с того места, граница записей уедет, и фильтр склеит ClientHello
     * обратно — техника та же, а обхода нет.
     */
    @Test
    fun repackRecordAtCutsAtTheExactOffset() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        val recLen = Tls.recordTotalLength(hello, 0, hello.size)
        assertTrue("в тесте нужен корректный ClientHello", recLen > 0)
        val bodyLen = recLen - Tls.RECORD_HEADER
        val at = Tls.RECORD_HEADER + bodyLen / 3

        val out = Tls.repackRecordAt(hello, 0, hello.size, at)
        assertTrue("рез по смещению обязан сработать", out != null)
        out!!

        val bounds = Tls.recordBoundaries(out, 0, out.size)
        assertEquals("ожидались ровно две записи", 2, bounds.size)

        // Граница между записями — ровно запрошенная точка.
        val firstRecLen = getU16(out, 3)
        assertEquals("граница записей должна быть там, где просили", at, Tls.RECORD_HEADER + firstRecLen)
        assertEquals("тело второй записи — остаток", recLen - at, getU16(out, at + 3))
    }

    /** Рез не должен ни терять, ни дублировать байты. */
    @Test
    fun repackRecordAtPreservesBody() {
        val hello = StrategyAutopilotHelloFactory.build("rr1---sn-gxuo03g-ig3s.googlevideo.com")
        val recLen = Tls.recordTotalLength(hello, 0, hello.size)
        assertTrue("в тесте нужен корректный ClientHello", recLen > 0)
        val at = Tls.RECORD_HEADER + (recLen - Tls.RECORD_HEADER) / 2

        val out = Tls.repackRecordAt(hello, 0, hello.size, at) ?: error("рез не сработал")
        // Тела обеих частей подряд — без заголовков: recordBoundaries отдаёт
        // КОНЦЫ записей, складывать по ним тела напрямую нельзя.
        val firstLen = getU16(out, 3)
        val part1 = out.copyOfRange(Tls.RECORD_HEADER, Tls.RECORD_HEADER + firstLen)
        val secondStart = Tls.RECORD_HEADER + firstLen
        val secondLen = getU16(out, secondStart + 3)
        val part2 = out.copyOfRange(secondStart + Tls.RECORD_HEADER, secondStart + Tls.RECORD_HEADER + secondLen)
        val rebuilt = part1 + part2
        assertArrayEquals(
            "тело записи обязано собраться обратно без потерь",
            hello.copyOfRange(Tls.RECORD_HEADER, recLen),
            rebuilt
        )
    }

    /**
 * `repackRecordInPlace` обязан совпадать с алгоритмом ZapretYT побайтово.
 *
 * Эталон — их декомпилированный код (`AbstractC0148g.a()`): тело разрывается
 * в точке `cut`, после чего перед второй частью ВСТАВЛЯЕТСЯ заголовок записи —
 * тип и версия копируются из первой, длины переписываются. Метод отличается от
 * [Tls.repackRecordAt] только формой, результат обязан быть тот же.
 *
 * Проверка важна потому, что вариант с потерянными байтами заголовка
 * компилируется и работает, но тихо укорачивает первую запись на 3 байта —
 * это ловится только сравнением с эталоном.
 */
@Test
fun repackRecordInPlaceMatchesReferenceAlgorithm() {
    val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
    val recLen = Tls.recordTotalLength(hello, 0, hello.size)
    val cut = (recLen - Tls.RECORD_HEADER) / 3

    val actual = Tls.repackRecordInPlace(hello, 0, hello.size, cut)
    assertNotNull("переупаковка обязана сработать", actual)
    val repacked = actual ?: error("переупаковка не сработала")

    // Эталон: вставка заголовка внутрь исходного буфера со сдвигом тела.
    // Буфер сначала расширяется (как их Arrays.copyOf с запасом): сдвигать
    // вправо внутри массива исходного размера некуда — будет AIOOBE.
    val buf = hello.copyOf(hello.size + Tls.RECORD_HEADER)
    val rest = recLen - Tls.RECORD_HEADER - cut
    System.arraycopy(buf, Tls.RECORD_HEADER + cut, buf, Tls.RECORD_HEADER + cut + 5, rest)
    System.arraycopy(buf, 0, buf, Tls.RECORD_HEADER + cut, 3)
    buf[3] = (cut shr 8).toByte(); buf[4] = cut.toByte()
    buf[Tls.RECORD_HEADER + cut + 3] = (rest shr 8).toByte()
    buf[Tls.RECORD_HEADER + cut + 4] = rest.toByte()

    assertArrayEquals(
        "переупаковка обязана совпасть с эталоном ZapretYT",
        buf, repacked
    )
    assertEquals(
        "записей ровно две, каждая с заголовком",
        2, Tls.recordBoundaries(repacked, 0, repacked.size).size
    )
}

/** Точка вне тела записи — не повод резать наугад. */
    @Test
    fun repackRecordAtRejectsOffsetsOutsideBody() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        assertNull("смещение в заголовке отвергается", Tls.repackRecordAt(hello, 0, hello.size, 3))
        assertNull("смещение за концом записи отвергается", Tls.repackRecordAt(hello, 0, hello.size, hello.size))
    }

    /** После переупаковки SNI разбирается заново: смещения сдвинуты. */
    @Test
    fun sniSurvivesRepacking() {
        val hello = StrategyAutopilotHelloFactory.build("rr1---sn-gxuo03g-ig3s.googlevideo.com")
        val plan = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(
                desync = DesyncMode.MULTISPLIT_TLSREC,
                tlsrecParts = 2,
                splitPositions = listOf(SplitPos.MIDSNI)
            )
        )
        assertTrue("стратегия обязана применяться", plan.applied)
        val rebuilt = plan.writes.fold(ByteArray(0)) { acc, w -> acc + w }
        // Сегменты склеиваются в переупакованный поток, где SNI лежит на
        // границе записей. Парсер несколько записей не склеивает, поэтому
        // перед разбором собираем ТЕЛА записей (recordBoundaries отдаёт КОНЦЫ,
        // последний равен размеру — записью он не является).
        val ends = Tls.recordBoundaries(rebuilt, 0, rebuilt.size)
        var prev = 0
        val bodies = java.io.ByteArrayOutputStream()
        for (e in ends) {
            if (e > rebuilt.size) break
            val len = getU16(rebuilt, prev + 3)
            if (prev + Tls.RECORD_HEADER + len > rebuilt.size) break
            bodies.write(rebuilt, prev + Tls.RECORD_HEADER, len)
            prev = e
        }
        // Парсер ждёт целую TLS-запись, а не голые тела: собираем корректную
        // одиночную запись (версия — из исходной, длина — по факту тел).
        val raw = bodies.toByteArray()
        val defrag = byteArrayOf(0x16, rebuilt[1], rebuilt[2], (raw.size ushr 8).toByte(), raw.size.toByte()) + raw
        assertEquals(
            "SNI обязан остаться читаемым после переупаковки",
            "rr1---sn-gxuo03g-ig3s.googlevideo.com",
            Tls.parseClientHello(defrag, 0, defrag.size)?.sni
        )
    }

    /**
     * Профильная стратегия обязана давать ровно тот образ, что у победителя
     * `--tlsrec=0+wm --split=0+wm`: два сегмента, каждый начинается с заголовка
     * TLS-записи, разрыв ровно на границе записей.
     *
     * Регрессия: пересчёт MIDSNI после вставки заголовка давал точку M+5 вместо
     * M, и поток рвался трижды — посередине ехал одинокий 5-байтовый заголовок
     * второй записи. Байтовый поток тот же, а сегментация уже не та, что
     * проходила фильтр.
     */
    @Test
    fun profileStrategyEmitsExactlyTwoRecordAlignedSegments() {
        val hello = StrategyAutopilotHelloFactory.build("www.youtube.com")
        val plan = engine.plan(
            hello, FlowContext(443, null, false),
            Strategy(
                desync = DesyncMode.MULTISPLIT_TLSREC,
                tlsrecParts = 2,
                splitPositions = listOf(SplitPos.MIDSNI)
            )
        )
        assertTrue("стратегия обязана применяться", plan.applied)
        assertEquals(
            "ожидались ровно 2 сегмента (граница записей), получено ${plan.writes.size}",
            2, plan.writes.size
        )
        for ((i, w) in plan.writes.withIndex()) {
            assertEquals(
                "сегмент $i обязан начинаться с заголовка TLS-записи (0x16)",
                0x16, w[0].toInt() and 0xFF
            )
        }
        assertEquals(
            "переупаковка добавляет ровно один заголовок",
            hello.size + Tls.RECORD_HEADER, plan.writes.sumOf { it.size }
        )
    }
}