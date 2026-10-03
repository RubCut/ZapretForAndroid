import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
}

/* ---------------------------------------------------------------------------
 * Подпись релизной сборки.
 *
 * Ключ лежит в keystore/release.p12 и зафиксирован в репозитории: это даёт
 * одинаковую подпись у локальной сборки, у CI и у следующих версий, поэтому
 * APK ставится поверх предыдущего без удаления и без потери данных.
 *
 * Приоритет источников параметров:
 *   1. -PZAPRET_* / gradle.properties
 *   2. переменная окружения ZAPRET_*
 *   3. keystore/signing.properties
 *   4. запасное значение
 *
 * Если keystore вдруг отсутствует, релиз подписывается debug-ключом — сборка
 * не падает, но в логе появляется предупреждение.
 * ------------------------------------------------------------------------- */
val fileProps = Properties().apply {
    val f = rootProject.file("keystore/signing.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

fun signProp(name: String, fallback: String): String =
    providers.gradleProperty(name).orNull?.takeIf { it.isNotBlank() }
        ?: System.getenv(name)?.takeIf { it.isNotBlank() }
        ?: fileProps.getProperty(name)?.takeIf { it.isNotBlank() }
        ?: fallback

val releaseStoreFile = rootProject.file(signProp("ZAPRET_STORE_FILE", "keystore/release.p12"))
val releaseSigningReady = releaseStoreFile.exists()

if (!releaseSigningReady) {
    logger.warn("ZapretForAndroid: ${'$'}releaseStoreFile не найден — релиз будет подписан debug-ключом")
}

android {
    namespace = "dev.rubcut.zapret"
    compileSdk = 35

    defaultConfig {
        applicationId = "dev.rubcut.zapret"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        // Метка коммита, из которого собран APK: CI передаёт GIT_SHA из
        // github.sha. По ней в журнале и на экране «О приложении» видно,
        // какая именно сборка стоит на устройстве.
        buildConfigField("String", "GIT_SHA", "\"" + (System.getenv("GIT_SHA") ?: "dev") + "\"")

        vectorDrawables.useSupportLibrary = true
    }

    signingConfigs {
        if (releaseSigningReady) {
            create("release") {
                storeFile = releaseStoreFile
                storePassword = signProp("ZAPRET_STORE_PASSWORD", "")
                keyAlias = signProp("ZAPRET_KEY_ALIAS", "zapret")
                keyPassword = signProp("ZAPRET_KEY_PASSWORD", "")
                // V1 нужен отдельным OEM-установщикам, V2/V3 — современная схема.
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
                enableV4Signing = false
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = if (releaseSigningReady) {
                signingConfigs.getByName("release")
            } else {
                signingConfigs.getByName("debug")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        isCoreLibraryDesugaringEnabled = false
    }

    kotlinOptions {
        jvmTarget = "17"
        freeCompilerArgs += listOf("-opt-in=kotlin.RequiresOptIn")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/DEPENDENCIES",
                "META-INF/*.kotlin_module"
            )
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.service)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.documentfile)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.kotlinx.coroutines.android)
}
