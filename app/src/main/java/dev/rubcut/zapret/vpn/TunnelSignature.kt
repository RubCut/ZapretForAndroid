package dev.rubcut.zapret.vpn

import dev.rubcut.zapret.data.AppConfig

/**
 * Конфиг с MTU, ужатым до возможностей физической сети.
 *
 * Ужимается не только для стеков ([ZapretVpnService.tunnelConfig]), но и для
 * сигнатуры перезапуска: в репозитории MTU остаётся заданным (например, 1500),
 * а туннель живёт с ужатым (1430). Пока сигнатура сохранялась от ужатого
 * конфига, а наблюдатель сравнивал её с сырым, первый же эмит конфига выглядел
 * как «смена настроек»: туннель перезапускался каждые ~350 мс, и весь трафик
 * (включая зонды автоподбора) умирал, не успев установиться. Проявлялось ровно
 * на сетях, где физический MTU ниже заданного.
 */
internal fun effectiveMtuConfig(cfg: AppConfig, mtuCap: Int): AppConfig =
    if (cfg.mtu > mtuCap) cfg.copy(mtu = mtuCap) else cfg

/**
 * Отпечаток параметров, требующих пересоздания туннеля.
 *
 * Таймауты и буферы живые (читаются на каждое новое соединение) и перезапуска
 * не требуют; конечные точки DNS и UDP-политика привязаны к `establish()` —
 * поэтому входят в отпечаток.
 *
 * Сравнивать отпечатки можно только от одинаково ужатого конфига
 * ([effectiveMtuConfig]): иначе туннель уходит в вечный перезапуск.
 */
internal fun tunnelSignatureOf(cfg: AppConfig): String =
    listOf(
        cfg.mtu, cfg.ipv4, cfg.ipv6, cfg.appScope,
        cfg.appPackages.sorted().joinToString(","),
        cfg.profile,
        cfg.dnsMode, cfg.dohUrl, cfg.dotHost, cfg.dnsServers, cfg.dnsHijack,
        cfg.udpMode, cfg.blockQuic, cfg.fakeUdp
    ).joinToString("|")
