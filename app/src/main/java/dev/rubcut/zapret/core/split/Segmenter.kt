package dev.rubcut.zapret.core.split

/**
 * Разбиение полосы байтов по заданным смещениям.
 *
 * Вынесено отдельно, потому что это единственное место, где решается, какие
 * именно фрагменты уйдут в сокет по отдельности, — то есть сама суть
 * десинхронизации. Его легко испортить, поэтому оно покрыто тестами.
 */
object Segmenter {

    /**
     * Режет [data] по смещениям [positions].
     *
     * Смещения трактуются как границы между фрагментами: фрагмент заканчивается
     * перед байтом с этим индексом. Порядок не важен — границы сортируются, —
     * но повторы и выход за пределы полосы отбрасываются.
     *
     * Точки за пределами данных пропускаются, а не приводят к ошибке: при
     * неполном ClientHello часть смещений недостижима, и оставшиеся всё равно
     * должны дать разбиение.
     */
    fun split(data: ByteArray, positions: List<Int>): List<ByteArray> {
        if (data.isEmpty()) return emptyList()
        val bounds = positions.asSequence()
            .filter { it > 0 && it < data.size }
            .distinct()
            .sorted()
            .toList()
        if (bounds.isEmpty()) return listOf(data)

        val out = ArrayList<ByteArray>(bounds.size + 1)
        var prev = 0
        for (p in bounds) {
            if (p <= prev) continue
            out += data.copyOfRange(prev, p)
            prev = p
        }
        if (prev < data.size) out += data.copyOfRange(prev, data.size)
        return out
    }
}