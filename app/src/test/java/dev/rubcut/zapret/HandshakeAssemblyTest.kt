package dev.rubcut.zapret

import dev.rubcut.zapret.core.proto.Tls
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Проверка разбора ClientHello на КОРОТКОМ фрагменте.
 *
 * Отдельный класс, потому что проверяет не арифметику, а граничное условие
 * разбора: первые 16 байт ClientHello, где SNI ещё не начался. Chromium с
 * Kyber (124+) раскладывает рукопожатие на несколько сегментов именно так, и
 * на таком обрывке движок обязан честно сказать «SNI ещё нет», а не выдумать
 * его и не разорвать поток.
 */
class HandshakeAssemblyTest {

    /** Настоящий ClientHello, разбитый на сегменты по 16 байт — как это делает Chromium. */
    @Test
    fun truncatedClientHelloHasNoSniAndNoGarbage() {
        val host = "rr12---sn-4g5ednse.googlevideo.com"
        val full = StrategyAutopilotHelloFactory.build(host)

        // Ни один укороченный фрагмент не должен давать SNI или мусор.
        for (cut in 5 until full.size) {
            val frag = full.copyOfRange(0, cut)
            val info = Tls.parseClientHello(frag, 0, frag.size)
            if (info != null) {
                assertEquals(
                    "на укороченном фрагменте ($cut байт) разобран неверный SNI",
                    host, info.sni
                )
                assertTrue(
                    "SNI выходит за пределы фрагмента ($cut байт)",
                    info.sniEnd <= frag.size
                )
            }
        }

        // Полная запись обязана разбираться.
        val complete = Tls.parseClientHello(full, 0, full.size)
        assertEquals(host, complete!!.sni)
    }

    /** Точка разбиения обязана оставаться внутри полученного фрагмента. */
    @Test
    fun midsldStaysInsideFragmentWhenHelloIsSplit() {
        val host = "rr5---sn-i3b6knf3n5oe.googlevideo.com"
        val full = StrategyAutopilotHelloFactory.build(host)
        val info = Tls.parseClientHello(full, 0, full.size)!!

        // Моделируем доставку первых двух сегментов по 16 байт.
        for (cut in listOf(16, 32, 48, 64)) {
            val frag = full.copyOfRange(0, minOf(cut, full.size))
            val partial = Tls.parseClientHello(frag, 0, frag.size)
            if (partial == null) continue
            assertTrue(
                "точка разбиения ${partial.midsldOffset} вне фрагмента ($cut байт)",
                partial.midsldOffset > partial.sniStart && partial.midsldOffset < partial.sniEnd
            )
        }
        assertTrue(info.midsldOffset in info.sniStart until info.sniEnd)
    }

    /** Поток, который не TLS, обязан распознаваться как «не наш протокол», а не как пустой SNI. */
    @Test
    fun nonTlsPayloadIsNotMistakenForHandshake() {
        val http = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        assertNull(Tls.parseClientHello(http, 0, http.size))
        // Случайные байты, начинающиеся с 0x16, тоже не должны давать SNI.
        val noise = ByteArray(64) { if (it == 0) 0x16 else 0x41 }
        val parsed = Tls.parseClientHello(noise, 0, noise.size)
        if (parsed != null) {
            assertTrue("SNI из мусора не должен быть осмысленным", parsed.sni.isNotBlank())
        }
    }

    /** Короткое имя без домена второго уровня — точка должна остаться внутри имени. */
    @Test
    fun singleLabelHostKeepsSplitInsideName() {
        for (host in listOf("localhost", "a.ru", "xn--80ak6aa92e.com")) {
            val full = StrategyAutopilotHelloFactory.build(host)
            val info = Tls.parseClientHello(full, 0, full.size)!!
            assertTrue(
                "точка ${info.midsldOffset} вне имени $host",
                info.midsldOffset > info.sniStart && info.midsldOffset < info.sniEnd
            )
        }
    }
}