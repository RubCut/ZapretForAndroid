package dev.rubcut.zapret

import dev.rubcut.zapret.data.AppConfig
import dev.rubcut.zapret.data.CURRENT_CONFIG_VERSION
import dev.rubcut.zapret.data.DnsMode
import dev.rubcut.zapret.data.ProfileId
import dev.rubcut.zapret.data.migrateConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * Миграция конфигурации при смене схемы.
 *
 * Главный дефект, который здесь закрывается: прежняя версия при сбое DoH
 * писала `dnsMode = SYSTEM` НАВСЕГДА. DNS провайдера подменяет адреса, и
 * застрявший SYSTEM означал, что любые адреса в приложении — мусорные.
 * На устройстве это выглядело так: `example.com` приходил как `8.47.69.1`,
 * и «Проверка связи» по такому адресу всегда говорила «ответа нет».
 */
class ConfigMigrationTest {

    /** DNS, застрявший в SYSTEM, обязан вернуться к рабочему режиму. */
    @Test
    fun stuckSystemDnsIsRestored() {
        val old = AppConfig(profile = ProfileId.COMBINED, dnsMode = DnsMode.SYSTEM, configVersion = 2)
        val after = migrateConfig(old)
        assertNotEquals(
            "DNS, застрявший в SYSTEM из-за бага автоотката, обязан быть возвращён",
            DnsMode.SYSTEM, after.dnsMode
        )
        assertEquals("схема обязана обновиться", CURRENT_CONFIG_VERSION, after.configVersion)
    }

    /** То же и для CUSTOM-конфигурации — профиль там не при чём. */
    @Test
    fun stuckSystemDnsIsRestoredForCustomProfile() {
        val old = AppConfig(profile = ProfileId.CUSTOM, dnsMode = DnsMode.SYSTEM, configVersion = 2)
        assertNotEquals(DnsMode.SYSTEM, migrateConfig(old).dnsMode)
    }

    /** Явный выбор пользователя (DoH/DoT) миграция трогать не должна. */
    @Test
    fun explicitDnsChoiceSurvivesMigration() {
        val old = AppConfig(profile = ProfileId.COMBINED, dnsMode = DnsMode.DOT, configVersion = 2)
        assertEquals(
            "выбранный пользователем DNS обязан сохраниться",
            DnsMode.DOT, migrateConfig(old).dnsMode
        )
    }

    /** Свежая конфигурация не должна переписываться. */
    @Test
    fun currentConfigIsUntouched() {
        val cur = AppConfig(profile = ProfileId.CUSTOM, dnsMode = DnsMode.SYSTEM)
        val after = migrateConfig(cur)
        assertEquals("актуальная схема не должна меняться", cur.dnsMode, after.dnsMode)
        assertEquals(cur.rules, after.rules)
    }
}