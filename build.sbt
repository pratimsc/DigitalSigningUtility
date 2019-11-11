//import AssemblyKeys._ // put this at the top of the file

//assemblySettings

name := "DigitalSigningUtility"

version := "0.1.0"

scalaVersion := "2.12.10"

exportJars := true

//jarName in assembly := "digitalSigningUtility." + version

scalacOptions ++= Seq("-deprecation", "-feature","-target:jvm-13")

libraryDependencies += "org.scalatest" %% "scalatest" % "3.0.8" % "test"

libraryDependencies += "org.slf4j" % "slf4j-api" % "1.7.29"

libraryDependencies += "ch.qos.logback" % "logback-core" % "1.2.3"

libraryDependencies += "ch.qos.logback" % "logback-classic" % "1.2.3"

libraryDependencies += "joda-time" % "joda-time" % "2.10.5"

libraryDependencies += "org.joda" % "joda-convert" % "1.3.1"

libraryDependencies += "org.bouncycastle" % "bcprov-jdk15on" % "1.64"
