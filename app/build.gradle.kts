import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.resign.pro"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.resign.pro"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        vectorDrawables {
            useSupportLibrary = true
        }

        ndk {
            abiFilters += listOf("arm64-v8a")
        }

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17 -fno-exceptions -fno-rtti"
                arguments += listOf(
                    "-DANDROID_STL=c++_static",
                    "-DANDROID_PLATFORM=android-24"
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlinOptions {
        jvmTarget = "1.8"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.1"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
            useLegacyPackaging = true
        }
    }

    sourceSets {
        getByName("main") {
            assets.srcDir(layout.buildDirectory.dir("generated/payloadAssets"))
        }
    }
}

// payload AAR 依赖提取（用于编译 HookEntry.java）
val payloadAars by configurations.creating
dependencies {
    payloadAars("top.canyie.pine:core:0.3.0")
    payloadAars("top.canyie.pine:xposed:0.2.0")
    payloadAars("top.canyie.pine:enhances:0.1.0")
}

tasks.register("preparePayloadDeps") {
    val outDir = layout.buildDirectory.dir("payload-deps")
    outputs.dir(outDir)
    doLast {
        val dir = outDir.get().asFile
        dir.mkdirs()
        payloadAars.resolve().forEach { aar ->
            copy {
                from(zipTree(aar))
                into(dir.resolve(aar.nameWithoutExtension))
                include("classes.jar")
            }
        }
    }
}

val payloadSrcDir = rootProject.layout.projectDirectory.dir("payload")
val payloadDepsDir = layout.buildDirectory.dir("payload-deps")
val payloadClassesDir = layout.buildDirectory.dir("payload-classes")
val payloadJarDir = layout.buildDirectory.dir("payload-jar")
val payloadDexWorkDir = layout.buildDirectory.dir("payload-dex")
val payloadAssetsOutDir = layout.buildDirectory.dir("generated/payloadAssets/resign_pro")
val payloadDexOutFile = payloadAssetsOutDir.map { it.file("classesx.dex") }

val compilePayloadJava = tasks.register<JavaCompile>("compilePayloadJava") {
    dependsOn("preparePayloadDeps")
    source = fileTree(payloadSrcDir) { include("**/*.java") }
    destinationDirectory.set(payloadClassesDir)
    sourceCompatibility = "11"
    targetCompatibility = "11"
    classpath = files(android.bootClasspath) + fileTree(payloadDepsDir) { include("**/classes.jar") }
}

val jarPayloadClasses = tasks.register<org.gradle.jvm.tasks.Jar>("jarPayloadClasses") {
    dependsOn(compilePayloadJava)
    from(payloadClassesDir)
    destinationDirectory.set(payloadJarDir)
    archiveFileName.set("payload-classes.jar")
}

val buildPayloadDex = tasks.register("buildPayloadDex") {
    dependsOn(jarPayloadClasses)
    inputs.dir(payloadSrcDir)
    inputs.dir(payloadDepsDir)
    outputs.file(payloadDexOutFile)
    doLast {
        val sdkDir = android.sdkDirectory
        val buildToolsRoot = File(sdkDir, "build-tools")
        val buildTools = buildToolsRoot.listFiles()
            ?.filter { it.isDirectory }
            ?.sortedBy { it.name }
            ?.lastOrNull()
            ?: throw GradleException("No build-tools found under: ${buildToolsRoot.absolutePath}")
        val d8 = File(buildTools, "d8")
        if (!d8.exists()) throw GradleException("d8 not found: ${d8.absolutePath}")

        val dexWork = payloadDexWorkDir.get().asFile
        dexWork.deleteRecursively()
        dexWork.mkdirs()

        val jarFile = jarPayloadClasses.get().archiveFile.get().asFile
        if (!jarFile.exists() || jarFile.length() <= 0) {
            throw GradleException("payload jar not generated")
        }

        exec {
            val args = mutableListOf(
                d8.absolutePath,
                "--min-api", "21",
                "--output", dexWork.absolutePath
            )
            android.bootClasspath.forEach { lib ->
                args.addAll(listOf("--lib", lib.absolutePath))
            }
            fileTree(payloadDepsDir).matching { include("**/classes.jar") }.files.forEach { cp ->
                args.addAll(listOf("--classpath", cp.absolutePath))
            }
            args.add(jarFile.absolutePath)
            commandLine(args)
        }

        val classesDex = File(dexWork, "classes.dex")
        if (!classesDex.exists() || classesDex.length() <= 0) {
            throw GradleException("payload classes.dex not generated")
        }

        val outDir = payloadAssetsOutDir.get().asFile
        outDir.mkdirs()
        classesDex.copyTo(payloadDexOutFile.get().asFile, overwrite = true)
    }
}

tasks.named("preBuild") {
    dependsOn(buildPayloadDex)
}

dependencies {
    // AndroidX
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.multidex:multidex:2.0.1")

    // Compose
    implementation(platform("androidx.compose:compose-bom:2023.08.00"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")

    // Pine（Java Hook框架）
    implementation("top.canyie.pine:core:0.3.0")
    implementation("top.canyie.pine:xposed:0.2.0")
    implementation("top.canyie.pine:enhances:0.1.0")

    // DEX处理
    implementation("com.android.tools.smali:smali-dexlib2:3.0.3")
    implementation("org.smali:dexlib2:2.5.2")

    // ZIP处理
    implementation("net.lingala.zip4j:zip4j:2.11.5")

    // APK签名
    implementation("com.android.tools.build:apksig:8.2.2")
    implementation("org.bouncycastle:bcpkix-jdk15to18:1.70")
    implementation("org.bouncycastle:bcprov-jdk15to18:1.70")

    // Manifest编辑
    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))

    // 测试
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
    debugImplementation("androidx.compose.ui:ui-tooling")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
