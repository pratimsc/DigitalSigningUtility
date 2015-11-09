package org.barclays.ifsdigsig

import java.security.Security
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyStore
import java.security.PublicKey
import java.io.File
import java.io.FileInputStream
import java.security.PrivateKey
import java.security.Signature
import java.security.MessageDigest
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.params.RSAKeyParameters
import java.security.interfaces.RSAPublicKey

object SigUtility {

  Security.addProvider(new BouncyCastleProvider())
  val CRYPTO_PROVIDER = new BouncyCastleProvider

  def main(args: Array[String]): Unit = {
    val keyStoreFile = """B:\PKI\X509\test.keystore"""
  }

  /**
   * Get the KeyStore from file. The supported keystore is Java keystore only.
   */
  def getKeyStore(keyFile: File, keyFileSecret: String): KeyStore = {
    val fin = new FileInputStream(keyFile)
    val keyStore = KeyStore.getInstance("JKS")
    keyStore.load(fin, keyFileSecret.toCharArray())
    keyStore
  }

  /**
   * Fetch the available public key from the provided keystore
   */

  def fetchPublicKeyFromKeyStore(keyStore: KeyStore, keyId: String): Option[PublicKey] = (keyStore, keyId) match {
    case (ks, id) =>
      val pubCert = ks.getCertificate(id)
      val pubKey = pubCert.getPublicKey()
      Some(pubKey)
    case _ => None
  }

  /**
   * Fetch the available private key from the provided keystore
   */

  def fetchPrivateKeyFromKeyStore(keyStore: KeyStore,
    privateKeyAlias: String,
    privateKeyPassword: String): Option[PrivateKey] = (keyStore, privateKeyAlias, privateKeyPassword) match {
    case (ks, key, pass) =>
      ks.getKey(key, pass.toCharArray()) match {
        case null => None
        case key => Some(key.asInstanceOf[PrivateKey])
      }
    case _ => None
  }

  /**
   * Verify the digital signature of the signed data
   */

  def verifyDigitalSignatureOfData(signedData: Array[Byte],
    signatureData: Array[Byte],
    publicKey: PublicKey,
    signatureAlgorithm: String): Boolean = (signedData, signatureData, publicKey, signatureAlgorithm) match {
    case (data, sign, key, alg) =>
      alg match {
        case null =>
          verifyDigitalSignatureOfData(data, sign, key, key.getAlgorithm())
        case _ =>
          val sigVerifier = Signature.getInstance(alg,CRYPTO_PROVIDER)
          sigVerifier.initVerify(key)
          sigVerifier.update(data)          
          sigVerifier.verify(sign)
      }
    case _ => false
  }

  /**
   * Return decrypted value of the digital signature of the signed data
   */

  def decryptDigitalSignatureOfData(signatureData: Array[Byte],
    publicKey: PublicKey,
    signatureAlgorithm: String): String = (signatureData, publicKey, signatureAlgorithm) match {
    case (sign, key, alg) =>
      alg match {
        case null =>
          decryptDigitalSignatureOfData(sign, key, key.getAlgorithm())
        case _ =>
          val e:RSAEngine = new RSAEngine()
          val rsaKey = key.asInstanceOf[RSAPublicKey]
          val rsaKeyParameter = new RSAKeyParameters(false, rsaKey.getModulus(),rsaKey.getPublicExponent())          
          e.init(false,rsaKeyParameter)
          val decryptedByte = e.processBlock(sign, 0, sign.length)
          byteArray2HexString(decryptedByte)
      }
    case _ => ""
  }
  
  /**
   * Create a digital signature of the test data
   */
  def createDigitalSignatureOfData(data: Array[Byte],
    privateKey: PrivateKey,
    signatureAlgorithm: String): Option[Array[Byte]] = (privateKey, signatureAlgorithm) match {
    case (key, alg) =>
      val sig = Signature.getInstance(alg,CRYPTO_PROVIDER)
      sig.initSign(key)
      sig.update(data)
      Some(sig.sign())
    case _ => None
  }

  /**
   * Create HASH of the data.
   */
  def createHashSignatureOfData(data: Array[Byte], algorithm: String): Option[Array[Byte]] = (data, algorithm) match {
    case (d, alg) =>
      val md = MessageDigest.getInstance(alg,CRYPTO_PROVIDER)
      md.update(d)
      Some(md.digest())
    case _ => None
  }

  /**
   * Helper function to convert to Hex
   */
  def byteArray2HexString(bytes: Array[Byte]): String = bytes.map("%02X" format _).mkString

  /**
   * Helper function to convert to Array[Byte]
   */
  def hexString2ByteArray(hex: String): Array[Byte] = {
    if (hex.contains(" ")) {
      hex.split(" ").map(Integer.parseInt(_, 16).toByte)
    } else if (hex.contains("-")) {
      hex.split("-").map(Integer.parseInt(_, 16).toByte)
    } else {
      hex.sliding(2, 2).toArray.map(Integer.parseInt(_, 16).toByte)
    }
  }
}
