plugins {
    `java-library`
    `maven-publish`
}

group = "fr.delthas"
version = "1.1.3-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.whispersystems:signal-protocol-java:2.6.2")
    testImplementation("junit:junit:4.12")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8

    withJavadocJar()
    withSourcesJar()
}

publishing {
    repositories {
        maven {
            url = uri("https://mavenproxy.saucisseroyale.cc")
            credentials {
                username = project.properties["ftp.username"] as String? ?: ""
                password = project.properties["ftp.password"] as String? ?: ""
            }
        }
    }
    publications {
        create<MavenPublication>("maven") {
            pom {
                name.set("libsilence-java")
                description.set("Lightweight API for the Silence protocol")
                url.set("https://github.com/delthas/libsilence-java")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("http://www.opensource.org/licenses/mit-license.php")
                    }
                }
                developers {
                    developer {
                        name.set("delthas")
                        email.set("delthas@dille.cc")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:delthas/libsilence-java.git")
                    developerConnection.set("scm:git:git@github.com:delthas/libsilence-java.git")
                    url.set("git@github.com:delthas/libsilence-java.git")
                }
            }
            from(components["java"])
        }
    }
}
