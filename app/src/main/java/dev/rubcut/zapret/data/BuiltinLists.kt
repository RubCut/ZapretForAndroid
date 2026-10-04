package dev.rubcut.zapret.data

/**
 * Стартовые списки. Составлены по мотивам `lists/` из zapret-discord-youtube и
 * zapret-discord-youtube-linux; их можно полностью переопределить в приложении.
 */
object BuiltinLists {

    val GOOGLE = """
        google.com
        google.ru
        googleapis.com
        googlevideo.com
        googleusercontent.com
        googlesyndication.com
        googleadservices.com
        ggpht.com
        gstatic.com
        gvt1.com
        gvt2.com
        withyoutube.com
        youtube.com
        youtube-nocookie.com
        youtu.be
        ytimg.com
        yt.be
        recaptcha.net
        android.com
        play.google.com
        accounts.google.com
        lh3.googleusercontent.com
        s.youtube.com

        # Домены, без которых YouTube не грузится, хотя в названии нет слов
        # «google» или «youtube». Правило списка простое: запись без звёздочки
        # совпадает и со всеми поддоменами, поэтому отдельные записи для
        # rr*.googlevideo.com или *.ggpht.com не нужны — они уже покрыты
        # строками googlevideo.com и ggpht.com выше.
        youtubei.googleapis.com
        youtube.googleapis.com
        youtubekids.com
        musics.youtube.com
        tv.youtube.com
        studio.youtube.com
        redirector.googlevideo.com
        video.google.com
        # Реклама и статистика, на которых без неё YouTube показывает пустую страницу.
        doubleclick.net
        # Старый CDN YouTube, ещё используется частью клиентов.
        edgesuite.net
    """.trimIndent()

    val DISCORD = """
        discord.com
        discord.gg
        discordapp.com
        discordapp.net
        discordapp.io
        discord.media
        discordstatus.com
        discord.dev
        discord.new
        discord.gift
        discord.gifts
        discord.store
        discord.tools
        discordactivities.com
        discord-attachments.com
        dis.gd
        bigbeans.solutions
        watchanimeattheoffice.com
    """.trimIndent()

    val GENERAL: String = (GOOGLE + "\n" + DISCORD).trim()

    val EXCLUDE_EXAMPLE = """
        # Домены из этого списка не обрабатываются движком,
        # даже если совпали с основным hostlist.
        # Пример:
        # mail.google.com
    """.trimIndent()

    val IPSET_ALL = """
        # Google / YouTube (IPv4)
        64.233.160.0/19
        66.102.0.0/20
        66.249.64.0/19
        72.14.192.0/18
        74.125.0.0/16
        108.177.0.0/17
        142.250.0.0/15
        172.217.0.0/16
        173.194.0.0/16
        209.85.128.0/17
        216.58.192.0/19
        216.239.32.0/19
        # Discord (Cloudflare)
        162.159.128.0/21
        # Google (IPv6)
        2001:4860::/32
        2607:f8b0::/32
        2a00:1450::/32
    """.trimIndent()

    val IPSET_EXCLUDE_EXAMPLE = """
        # CIDR-диапазоны, которые движок не трогает.
        # Пример:
        # 192.168.0.0/16
    """.trimIndent()

    val HOSTS_EXAMPLE = """
        # Синтаксис файла hosts. Записи применяются внутри туннеля на этапе DNS:
        # приложение получит именно тот адрес, который указан здесь.
        #
        # Полезно, когда провайдер подменяет DNS-ответы или когда сервис
        # доступен только по определённому адресу.
        #
        # 142.250.74.206   www.google.com
        # 0.0.0.0          blocked.example.com
        # ::1              localhost
    """.trimIndent()

    val ADS_BLOCK = """
        doubleclick.net
        googlesyndication.com
        googleadservices.com
        google-analytics.com
        analytics.google.com
        googletagmanager.com
        googletagservices.com
        app-measurement.com
        adservice.google.com
        ads-twitter.com
        adsystem.amazon.com
        adnxs.com
        adroll.com
        criteo.com
        criteo.net
        scorecardresearch.com
        quantserve.com
        moatads.com
        rubiconproject.com
        pubmatic.com
        openx.net
        casalemedia.com
        smartadserver.com
        yandexadexchange.net
        mobile.yandexadexchange.net
        an.yandex.ru
        mc.yandex.ru
        top-fwz1.mail.ru
        ad.mail.ru
        vkads.ru
    """.trimIndent()

    val HOSTLIST_DEFAULT: String = GENERAL

    val GOOGLE_IPSET = """
        64.233.160.0/19
        66.102.0.0/20
        74.125.0.0/16
        108.177.0.0/17
        142.250.0.0/15
        172.217.0.0/16
        173.194.0.0/16
        209.85.128.0/17
        216.58.192.0/19
        216.239.32.0/19
        2001:4860::/32
        2607:f8b0::/32
        2a00:1450::/32
    """.trimIndent()

    val DISCORD_IPSET = """
        162.159.128.0/21
        35.224.0.0/16
    """.trimIndent()
}
