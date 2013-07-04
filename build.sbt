import AssemblyKeys._ // put this at the top of the file

assemblySettings

name := "DigitalSigningUtility"

version := "0.1.0"

scalaVersion := "2.10.1"

exportJars := true

jarName in assembly := "digitalSigningUtility." + version

scalacOptions ++= Seq("-deprecation", "-feature","-target:jvm-1.7")

libraryDependencies += "org.scalatest" %% "scalatest" % "1.9.1" % "test"

libraryDependencies += "junit" % "junit" % "4.10" % "test"

libraryDependencies += "org.slf4j" % "slf4j-api" % "1.7.5"

libraryDependencies += "ch.qos.logback" % "logback-core" % "1.0.12"

libraryDependencies += "ch.qos.logback" % "logback-classic" % "1.0.12"

libraryDependencies += "joda-time" % "joda-time" % "2.2"

libraryDependencies += "org.joda" % "joda-convert" % "1.3.1"

libraryDependencies += "org.bouncycastle" % "bcprov-jdk16" % "1.45"
