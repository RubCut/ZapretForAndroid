package dev.rubcut.zapret

import dev.rubcut.zapret.core.match.HostMatcher
import dev.rubcut.zapret.data.BuiltinLists
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Встроенный список хостов обязан покрывать то, с чем реально ходит клиент
 * YouTube. Проверка на настоящих именах, потому что именно на них список и
 * строился: если CDN-хост не попал в hostlist, движок применяет стратегию по
 * адресу из обратного кэша DNS, а тот для YouTube зачастую отсутствует — и
 * обход молча не срабатывает.
 */
class HostListCoverageTest {

    private val google = HostMatcher.parse(BuiltinLists.GOOGLE)
    private val general = HostMatcher.parse(BuiltinLists.GENERAL)

    /** Реальные имена, с которыми общается приложение и сайт YouTube. */
    private val youtubeHosts = listOf(
        "www.youtube.com",
        "m.youtube.com",
        "youtubei.googleapis.com",
        "www.youtube-nocookie.com",
        "youtu.be",
        // Видео идёт с CDN, имена случайные — именно они ломали разбиение.
        "rr12---sn-4g5ednse.googlevideo.com",
        "rr5---sn-i3b6knf3n5oe.googlevideo.com",
        "rr3---sn-8oagn5g5g5oe.googlevideo.com",
        "redirector.googlevideo.com",
        "i.ytimg.com",
        "yt3.ggpht.com",
        "s.ytimg.com",
        "www.gstatic.com",
        "play.google.com",
        "googleads.g.doubleclick.net",
        "clients6.google.com",
        "www.youtube.com.edgesuite.net"
    )

    @Test
    fun allRealYoutubeHostsMatchGoogleList() {
        val missed = youtubeHosts.filterNot { google.matches(it) }
        assertTrue(
            "эти хосты не попали в встроенный список, значит к ним не применится стратегия: $missed",
            missed.isEmpty()
        )
    }

    @Test
    fun googleHostsAlsoPresentInGeneralList() {
        val missed = youtubeHosts.filterNot { general.matches(it) }
        assertTrue("общий список (hostlist по умолчанию) тоже должен покрывать: $missed", missed.isEmpty())
    }

    /** Соседние домены трогать нельзя: это чужой трафик. */
    @Test
    fun unrelatedDomainsAreNotMatched() {
        for (host in listOf("example.com", "vk.com", "ya.ru", "mail.ru", "wikipedia.org")) {
            assertFalse("$host не должен считаться гугловым хостом", google.matches(host))
        }
    }

    /** Точное имя без звёздочки обязано покрывать поддомены — в этом суть списка. */
    @Test
    fun bareDomainCoversAllSubdomains() {
        assertTrue(google.matches("googlevideo.com"))
        assertTrue(google.matches("a.b.c.googlevideo.com"))
        assertTrue(google.matches("youtubei.googleapis.com"))
        assertTrue(google.matches("ggpht.com"))
    }
}