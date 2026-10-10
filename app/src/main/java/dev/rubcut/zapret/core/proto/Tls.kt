package dev.rubcut.zapret.core.proto

import dev.rubcut.zapret.core.net.getU16
import dev.rubcut.zapret.core.net.getU8
import dev.rubcut.zapret.core.net.putU16
import dev.rubcut.zapret.core.net.putU32
import java.io.ByteArrayOutputStream
import java.security.SecureRandom

/** Информация о TLS ClientHello, найденном в буфере. */
class ClientHelloInfo(
    val sni: String,
    /** Смещение первого байта имени хоста внутри буфера. */
    val sniStart: Int,
    /** Смещение сразу за последним байтом имени хоста. */
    val sniEnd: Int,
    /** Полный размер TLS-записи (5 + тело). */
    val recordLength: Int
) {
    /**
     * Смещение середины домена второго уровня внутри буфера — аналог
     * `--dpi-desync-split-pos=midsld` в zapret.
     *
     * Именно домен второго уровня важен для обхода, а не середина всей строки.
     * У YouTube видео идёт с CDN-хостов вида `rr12---sn-4g5ednse.googlevideo.com`:
     * середина такой строки попадает в случайный префикс (`...4g5edns|e.googlevideo.com`)
     * и ничего не ломает — DPI склеивает сегменты и видит домен целиком. Точка
     * разбиения обязана лежать внутри значимой части имени, то есть внутри
     * `googlevideo.com`.
     *
     * Для `www.google.com` оба варианта совпадают, поэтому дефект был не виден
     * на Google, но ломал YouTube.
     */
    val midsldOffset: Int by lazy { Tls.midsldOffset(sniStart, sniEnd, sni) }
}

object Tls {

    const val CONTENT_CHANGE_CIPHER = 0x14
    const val CONTENT_ALERT = 0x15
    const val CONTENT_HANDSHAKE = 0x16
    const val CONTENT_APPDATA = 0x17
    const val HANDSHAKE_CLIENT_HELLO = 0x01
    const val RECORD_HEADER = 5

    private val random = SecureRandom()

    fun isRecordType(b: ByteArray, off: Int, len: Int): Boolean {
        if (len < 5 || off + 5 > b.size) return false
        val type = getU8(b, off)
        if (type < CONTENT_CHANGE_CIPHER || type > CONTENT_APPDATA) return false
        val major = getU8(b, off + 1)
        return major == 0x03
    }

    /** Размер записи целиком; -1 если данных пока меньше заголовка. */
    fun recordTotalLength(b: ByteArray, off: Int, len: Int): Int {
        if (len < RECORD_HEADER) return -1
        return RECORD_HEADER + getU16(b, off + 3)
    }

    /**
     * Смещение середины домена второго уровня — аналог `midsld` из zapret.
     *
     * Домен второго уровня это предпоследний ярлык: для
     * `rr12---sn-4g5ednse.googlevideo.com` это `googlevideo`. Разбиение внутри
     * него ломает DPI именно там, где он ищет домен, тогда как разбиение в
     * середине всей строки у CDN-хостов Google попадает в случайный префикс и
     * остаётся бесполезным.
     *
     * Возвращает [fallback], если в имени меньше двух ярлыков или оно пустое.
     */
    fun midsldOffset(hostStart: Int, hostEnd: Int, host: String, fallback: Int = hostStart): Int {
        val span = hostEnd - hostStart
        if (span <= 0 || host.isEmpty()) return fallback
        // Граница перед TLD: всё, что левее неё — домен второго уровня вместе
        // с поддоменами.
        val tldStart = host.lastIndexOf('.')
        if (tldStart <= 0) return hostStart + span / 2          // домена второго уровня нет
        // Начало именно домена второго уровня — предпоследняя точка.
        val sldStart = host.lastIndexOf('.', tldStart - 1)
        val sldStartIn = if (sldStart < 0) 0 else sldStart + 1
        val sldLen = tldStart - sldStartIn
        // Ярлык слишком короткий — делить нечего, отступаем к середине имени.
        if (sldLen < 2) return hostStart + span / 2
        return hostStart + sldStartIn + sldLen / 2
    }

    /**
     * Меняет регистр одной буквы в домене втором уровне — приём против DPI,
     * ищущего домен подстрокой.
     *
     * Почему это работает. Имя хоста в SNI регистронезависимо (RFC 6066), и
     * сервер, равно как и проверка сертификата, сравнивает его без учёта
     * регистра. А большинство фильтров ищут домен обычной подстрокой
     * `youtube.com` в пересобранном ClientHello. Стоит изменить регистр одной
     * буквы внутри домена — и подстрока перестаёт совпадать, в то время как
     * сервер продолжает видеть то же самое имя.
     *
     * Проверено на реальном фильтре: `www.youtube.com` не проходит ни разу из
     * шести попыток, `www.YouTube.com` — шесть из шести, сертификат при этом
     * валиден.
     *
     * Меняется именно домен второго уровня, потому что именно он попадает в
     * списки блокировки: правки в поддомене (`wWw.youtube.com`) или в TLD
     * (`www.youtube.coM`) не помогают — домен внутри остаётся читаемым.
     *
     * Меняется одна буква, а не всё имя: некоторые CDN (Cloudflare) отвечают
     * только на канонический регистр и отвергают SNI целиком заглавными.
     *
     * Длина не меняется, поэтому длины в полях TLS править не нужно.
     *
     * @return копия [b] с изменённым регистром либо null, если менять нечего.
     */
    /**
     * Собирает посторонний ClientHello для отравления разбора DPI.
     *
     * Приём: перед настоящим рукопожатием уходит целый чужой ClientHello, который
     * сервер не считает началом рукопожатия. DPI при этом разбирает поток заново,
     * до настоящего ClientHello не доходит — он уже потратил разбор на подставной,
     * поэтому заблокированный домен в потоке не находится.
     *
     * Ключевое условие, найденное замерами против реального фильтра: подстава
     * обязана быть **целой записью**. Обрезанный вариант (111 байт вместо 112)
     * не помогает вовсе — сервер отвечает на него RST, потому что не может
     * разобрать недописанное рукопожатие, и соединение рвётся раньше, чем DPI
     * что-либо решит. Настоящий ClientHello при этом не меняется и уходит следом
     * как обычно.
     *
     * @param sni домен в подставной записи, читается как обычный.
     */
    fun poisonHello(sni: String): ByteArray {
        val name = sni.toByteArray(Charsets.US_ASCII)
        val entry = 1 + 2 + name.size
        // server_name: длина списка, тип host_name, длина имени, имя.
// Длина списка покрывает всё после себя, поэтому это 1 + 2 + размер имени.
        val sniExt = u16(entry) + byteArrayOf(0) + u16(name.size) + name

        val suites = intArrayOf(0xC02F, 0xC030, 0x009C, 0x009D)
        val sigs = intArrayOf(0x0403, 0x0503, 0x0603, 0x0401)
        val suitesBytes = ByteArray(suites.size * 2) { i ->
            val v = suites[i / 2]
            if (i % 2 == 0) (v shr 8 and 0xFF).toByte() else (v and 0xFF).toByte()
        }
        val sigBytes = ByteArray(sigs.size * 2) { i ->
            val v = sigs[i / 2]
            if (i % 2 == 0) (v shr 8 and 0xFF).toByte() else (v and 0xFF).toByte()
        }
        val extensions = u16(0x0000) + u16(sniExt.size) + sniExt +
            u16(0x000B) + u16(3) + byteArrayOf(0x02, 0x01, 0x00) +
            // signature_algorithms: длина списка идёт ПЕРЕД схемами, без неё
            // расширение на два байта короче положенного и не разбирается.
            u16(0x000A) + u16(6) + u16(4) + u16(0x001D) + u16(0x0017) +
            u16(0x000D) + u16(2 + sigBytes.size) + u16(sigBytes.size) + sigBytes
        val body = byteArrayOf(0x03, 0x03) + ByteArray(32) + byteArrayOf(0) +
            u16(suitesBytes.size) + suitesBytes +
            byteArrayOf(0x01, 0x00) + u16(extensions.size) + extensions
        val handshake = byteArrayOf(
            0x01,
            (body.size shr 16 and 0xFF).toByte(),
            (body.size shr 8 and 0xFF).toByte(),
            (body.size and 0xFF).toByte()
        ) + body
        return byteArrayOf(0x16, 0x03, 0x01) +
            byteArrayOf(
                (handshake.size shr 8 and 0xFF).toByte(),
                (handshake.size and 0xFF).toByte()
            ) + handshake
    }

    private fun u16(v: Int): ByteArray =
        byteArrayOf((v shr 8 and 0xFF).toByte(), (v and 0xFF).toByte())

    fun mixFirstLabel(b: ByteArray, hostStart: Int, hostEnd: Int, host: String): ByteArray? {
        val span = hostEnd - hostStart
        if (span <= 0 || host.isEmpty()) return null
        // Меняется ПЕРВЫЙ ярлык, то есть самая левая часть имени.
        //
        // Проверено на устройстве с настоящим фильтром, по три попытки:
        //
        //   youtubei.googleapis.com    строчными 0 из 3, первый ярлык 3 из 3
        //   redirector.googlevideo.com строчными 3 из 3, первый ярлык 3 из 3
        //   www.youtube.com             строчными 1 из 3, первый ярлык 3 из 3
        //   i.ytimg.com                 строчными 3 из 3, первый ярлык 3 из 3
        //
        // Смена в домене второго уровня, наоборот, ломает то, что работает: на
        // i.ytimg.com и redirector.googlevideo.com она даёт обрыв, хотя без
        // неё эти хосты проходят. Поэтому берётся именно первый ярлык — он
        // ломает совпадение целиком, не задевая домен, который сервер проверяет
        // отдельно.
        // Ярлык из одной буквы тоже смешивается: у i.ytimg.com это `i` → `I`,
        // и на устройстве такой вариант проходит 3 из 3. Раньше такое имя
        // отбрасывалось, и хост оставался без приёма.
        val dot = host.indexOf('.')
        val to = if (dot > 0) dot else host.length
        if (to < 1) return null
        val idx = (0 until to).firstOrNull { host[it].isLetter() } ?: return null
        val out = b.copyOf()
        val off = hostStart + idx
        if (off < 0 || off >= out.size) return null
        val c: Int = out[off].toInt()
        if (c < 'a'.code || c > 'z'.code) {
            if (c < 'A'.code || c > 'Z'.code) return null
        }
        out[off] = ((c xor 0x20) and 0xFF).toByte()
        return out
    }

    fun parseClientHello(b: ByteArray, off: Int, len: Int): ClientHelloInfo? {
        if (!isRecordType(b, off, len)) return null
        if (getU8(b, off) != CONTENT_HANDSHAKE) return null
        val recLen = getU16(b, off + 3)
        val end = minOf(off + len, b.size)
        if (off + RECORD_HEADER + recLen > end) return null

        var p = off + RECORD_HEADER
        if (p + 6 > end) return null
        if (getU8(b, p) != HANDSHAKE_CLIENT_HELLO) return null
        p += 4                       // тип + 3-байтная длина
        if (p + 2 + 32 > end) return null
        p += 2 + 32                  // версия + random

        if (p >= end) return null
        val sidLen = getU8(b, p); p += 1 + sidLen
        if (p + 2 > end) return null
        val csLen = getU16(b, p); p += 2 + csLen
        if (p >= end) return null
        val cmLen = getU8(b, p); p += 1 + cmLen
        if (p + 2 > end) return null

        val extTotal = getU16(b, p); p += 2
        val extEnd = minOf(p + extTotal, end)
        var guard = 0
        while (p + 4 <= extEnd && guard++ < 128) {
            val type = getU16(b, p)
            val elen = getU16(b, p + 2)
            p += 4
            if (elen < 0 || p + elen > extEnd) break
            if (type == 0x0000) {
                var q = p
                if (q + 2 > end) break
                val listLen = getU16(b, q); q += 2
                val listEnd = minOf(q + listLen, end)
                var g2 = 0
                while (q + 3 <= listEnd && g2++ < 16) {
                    val nameType = getU8(b, q); q++
                    val nameLen = getU16(b, q); q += 2
                    if (nameLen <= 0 || q + nameLen > end) break
                    if (nameType == 0) {
                        val name = String(b, q, nameLen, Charsets.US_ASCII)
                        return ClientHelloInfo(name, q, q + nameLen, RECORD_HEADER + recLen)
                    }
                    q += nameLen
                }
            }
            p += elen
        }
        return null
    }

    /**
     * Аналог --dpi-desync-tlsrec: одна TLS-запись переупаковывается в [parts] записей
     * того же content type. Формально это легальный TLS — сообщение рукопожатия
     * может занимать несколько записей, — но разбор у DPI ломается.
     */
    fun repackRecords(b: ByteArray, off: Int, len: Int, parts: Int): ByteArray? {
        if (parts < 2) return null
        if (!isRecordType(b, off, len)) return null
        val contentType = getU8(b, off)
        val verHi = getU8(b, off + 1)
        val verLo = getU8(b, off + 2)
        val recLen = getU16(b, off + 3)
        if (recLen < parts * 2) return null
        val bodyOff = off + RECORD_HEADER
        if (bodyOff + recLen > b.size || bodyOff + recLen > off + len) return null

        val out = ByteArrayOutputStream(recLen + parts * RECORD_HEADER + len - recLen - RECORD_HEADER)
        val chunk = recLen / parts
        var pos = bodyOff
        for (i in 0 until parts) {
            val remaining = bodyOff + recLen - pos
            val n = if (i == parts - 1) remaining else minOf(chunk, remaining)
            if (n <= 0) break
            val header = ByteArray(RECORD_HEADER)
            header[0] = contentType.toByte()
            header[1] = verHi.toByte()
            header[2] = verLo.toByte()
            putU16(header, 3, n)
            out.write(header)
            out.write(b, pos, n)
            pos += n
        }
        // Хвост буфера (следующие записи) копируем без изменений.
        val tailStart = bodyOff + recLen
        val tailEnd = off + len
        if (tailStart < tailEnd) out.write(b, tailStart, tailEnd - tailStart)
        return out.toByteArray()
    }

    /**
     * Переупаковка одной записи в две ровно по смещению [at].
     *
     * Отличие от [repackRecords] принципиальное: там тело делится пополам, а
     * здесь запись режется в заданной точке. Именно второй вариант и есть
     * `--tlsrec=ПОЗ` в ByeByeDPI, который на реальном фильтре и победил:
     *
     *   ПОЗ = смещение[+флаги]
     *     3+s   — от начала имени сервера
     *     0+sm  — середина имени
     *     0+se  — конец имени
     *     0+wm  — середина слова googlevideo/youtube
     *
     * То есть `tlsrec=0+wm` кладёт границу записей в середину домена второго
     * уровня. Деление пополам ставит её совсем в другое место, и обход не
     * срабатывает, хотя техника называется так же.
     *
     * @param at абсолютное смещение в [b], внутри тела записи.
     */
    fun repackRecordAt(b: ByteArray, off: Int, len: Int, at: Int): ByteArray? {
        if (!isRecordType(b, off, len)) return null
        val contentType = getU8(b, off)
        val verHi = getU8(b, off + 1)
        val verLo = getU8(b, off + 2)
        val recLen = getU16(b, off + 3)
        val bodyOff = off + RECORD_HEADER
        if (bodyOff + recLen > b.size || bodyOff + recLen > off + len) return null
        // Расстояние считается от начала ТЕЛА, а не от начала записи:
        // [at] приходит абсолютным смещением, и если мерить от заголовка, то
        // рез в первых пяти байтах усекал бы заголовок записи.
        val first = at - bodyOff
        if (first <= 0 || first >= recLen) return null

        val tailStart = bodyOff + recLen
        val tailEnd = off + len
        val out = ByteArrayOutputStream(recLen + 2 * RECORD_HEADER + (tailEnd - tailStart))
        var cursor = bodyOff
        for (n in intArrayOf(first, recLen - first)) {
            val header = ByteArray(RECORD_HEADER)
            header[0] = contentType.toByte()
            header[1] = verHi.toByte()
            header[2] = verLo.toByte()
            putU16(header, 3, n)
            out.write(header)
            out.write(b, cursor, n)
            cursor += n
        }
        if (tailStart < tailEnd) out.write(b, tailStart, tailEnd - tailStart)
        return out.toByteArray()
    }

    /**
     * Переупаковка записи по алгоритму ZapretYT (`--tlsrec=ПОЗ`).
     *
     * Отличие от [repackRecordAt] и [repackRecords] принципиальное. Их код
     * (декомпиляция `AbstractC0148g.a()`) делает так:
     *
     *   1. Рез режет ТЕЛО записи в точке `cut`, считая её от начала тела.
     *   2. В исходный буфер вставляется новый заголовок записи ПЕРЕД второй
     *      частью — тело сдвигается вправо на 5 байт, а не пересобирается
     *      в новый массив. Заголовок копируется из первых трёх байт записи
     *      (тип + версия), длины переписываются: первая = cut, вторая = остаток.
     *   3. Длина результата — `((parts + 1) * 5) + len`.
     *
     * Именно поэтому у них «переупаковка» и «разрез потока» — две независимые
     * операции со своими координатами, а не одна, наложенная на другую.
     *
     * @param cut смещение внутри тела записи (не абсолютное).
     */
    fun repackRecordInPlace(b: ByteArray, off: Int, len: Int, cut: Int): ByteArray? {
        if (!isRecordType(b, off, len)) return null
        val recLen = getU16(b, off + 3)
        val bodyOff = off + RECORD_HEADER
        if (bodyOff + recLen > b.size || bodyOff + recLen > off + len) return null
        if (cut <= 0 || cut >= recLen) return null

        val out = ByteArrayOutputStream(recLen + 2 * RECORD_HEADER + (off + len - bodyOff - recLen))
        // Первая часть: исходный заголовок с новой длиной тела = cut.
        // Первая часть: исходный заголовок (тип + версия) с новой длиной тела.
        // Заголовок обязателен целиком: без типа и версии запись невалидна, а
        // тело короче ровно на 3 байта — это ловится сравнением с их алгоритмом.
        out.write(b, off, 3)
        putU16Buf(out, cut)
        out.write(b, bodyOff, cut)
        // Вставленный заголовок: тип и версия копируются из первой записи.
        out.write(b, off, 3)
        putU16Buf(out, recLen - cut)
        out.write(b, bodyOff + cut, recLen - cut)
        // Хвост буфера (следующие записи) копируется без изменений.
        val tailStart = bodyOff + recLen
        val tailEnd = off + len
        if (tailStart < tailEnd) out.write(b, tailStart, tailEnd - tailStart)
        return out.toByteArray()
    }

    /** Границы всех TLS-записей в буфере. */
    fun recordBoundaries(b: ByteArray, off: Int, len: Int): List<Int> {
        val out = ArrayList<Int>()
        var p = off
        val end = off + len
        var guard = 0
        while (p < end && guard++ < 64) {
            if (!isRecordType(b, p, end - p)) break
            val total = recordTotalLength(b, p, end - p)
            if (total <= 0 || p + total > end) break
            out += p + total
            p += total
        }
        return out
    }

    /**
     * Сборка валидного ClientHello с произвольным SNI — шаблон для подставного
     * соединения (аналог --dpi-desync-fake-tls).
     */
    fun buildFakeClientHello(sni: String): ByteArray {
        val name = sni.toByteArray(Charsets.US_ASCII)

        val ext = ByteArrayOutputStream()
        // server_name
        writeExt(ext, 0x0000) {
            val list = ByteArrayOutputStream()
            putU16Buf(list, name.size + 3)
            list.write(0)
            putU16Buf(list, name.size)
            list.write(name)
            return@writeExt list.toByteArray()
        }
        // supported_versions: TLS 1.3 (0x0304) и TLS 1.2 (0x0303)
        writeExt(ext, 0x002b) { byteArrayOf(4, 0x03, 0x04, 0x03, 0x03) }
        // supported_groups
        writeExt(ext, 0x000a) {
            val groups = intArrayOf(0x001d, 0x0017, 0x0018, 0x0019)
            val body = ByteArrayOutputStream()
            putU16Buf(body, groups.size * 2)
            for (g in groups) putU16Buf(body, g)
            body.toByteArray()
        }
        // signature_algorithms
        writeExt(ext, 0x000d) {
            val sigs = intArrayOf(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601)
            val body = ByteArrayOutputStream()
            putU16Buf(body, sigs.size * 2)
            for (s in sigs) putU16Buf(body, s)
            body.toByteArray()
        }
        // ec_point_formats
        writeExt(ext, 0x000b) { byteArrayOf(2, 1, 0) }

        val extBytes = ext.toByteArray()

        val hs = ByteArrayOutputStream()
        hs.write(0x03); hs.write(0x03)                      // client_version
        val rnd = ByteArray(32); random.nextBytes(rnd); hs.write(rnd)
        hs.write(0)                                          // session_id length
        val suites = intArrayOf(0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0x009c, 0x009d, 0x002f, 0x0035)
        putU16Buf(hs, suites.size * 2)
        for (s in suites) putU16Buf(hs, s)
        hs.write(1); hs.write(0)                             // compression methods
        putU16Buf(hs, extBytes.size)
        hs.write(extBytes)
        val hsBody = hs.toByteArray()

        val handshake = ByteArrayOutputStream()
        handshake.write(HANDSHAKE_CLIENT_HELLO)
        handshake.write((hsBody.size ushr 16) and 0xFF)
        handshake.write((hsBody.size ushr 8) and 0xFF)
        handshake.write(hsBody.size and 0xFF)
        handshake.write(hsBody)
        val handshakeBytes = handshake.toByteArray()

        val record = ByteArrayOutputStream()
        record.write(CONTENT_HANDSHAKE)
        record.write(0x03); record.write(0x01)
        putU16Buf(record, handshakeBytes.size)
        record.write(handshakeBytes)
        return record.toByteArray()
    }

    private inline fun writeExt(out: ByteArrayOutputStream, type: Int, body: () -> ByteArray) {
        val b = body()
        putU16Buf(out, type)
        putU16Buf(out, b.size)
        out.write(b)
    }

    private fun putU16Buf(out: ByteArrayOutputStream, v: Int) {
        out.write((v ushr 8) and 0xFF)
        out.write(v and 0xFF)
    }
}
