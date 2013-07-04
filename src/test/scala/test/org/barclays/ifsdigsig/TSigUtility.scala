package test.org.barclays.ifsdigsig

import org.scalatest.FunSuite
import org.junit.runner.RunWith
import org.scalatest.FunSuite
import org.barclays.ifsdigsig.SigUtility
import java.io.File
import java.security.interfaces.RSAPublicKey
import java.security.Provider.Service
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class TSigUtility extends FunSuite {
  val file = new File("""B:\Official\PKI\X509_PoC\work\AMSTest\ifs.messageway.test""")
  val pass = "Password1234@"
  val ks = SigUtility.getKeyStore(file, pass)

  test("01 KeyStore can be accessed") {
    val aliases = ks.aliases()
    while (aliases.hasMoreElements()) {
      val alias = aliases.nextElement()
      println("01 Key store has ->\t" + alias)
      val key = SigUtility.fetchPublicKeyFromKeyStore(ks, alias)
      key match {
        case None =>
          assert(false)
        case Some(k) =>
          println(s"""01 KeyAlias is "$alias" and key details are -\n $k """)

          if (k.isInstanceOf[RSAPublicKey]) {
            println("""01  The Hex representation of Modulus of RSA key is	->""" + k.asInstanceOf[RSAPublicKey].getModulus().toString(16))
            println("""01	The Hex representation of Expone  of RSA key is	->""" + k.asInstanceOf[RSAPublicKey].getPublicExponent().toString(16))
          }
      }
    }
    assert(ks != null)
  }

  test("02A Fetch a 1024 public from a keystore") {
    val keyAlias = "1024_b5c271b4689703cf3a1cf2b8fb7a85c096e07493"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)
    key match {
      case None =>
        assert(false)
      case Some(k) =>
        println(s"""02A KeyAlias is "$keyAlias" and key details are -\n $k """)
        assert(true)
    }
  }

  test("02B Fetch a 2048 public from a keystore") {
    val keyAlias = "99800000007301000021_identity"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)
    key match {
      case None =>
        assert(false)
      case Some(k) =>
        println(s"""02B KeyAlias is "$keyAlias" and key details are -\n $k """)
        assert(true)
    }
  }

  test("03 Test SHA1 hash of the data") {
    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+051703861611+137:20130517:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+5170386161:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130517:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TEST  REFERENCE CHAPNAR1 CHAPNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val alg = "SHA1"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), alg)
    val refHash = "3CA6A8C93DB951683C25AE99B7C8BC8F0B567233"
    hash match {
      case None => assert(false)
      case Some(hv) =>
        val rHashHexStr = SigUtility.byteArray2HexString(hv)
        println("03 Calcuated SHA1 hash is ->\t" + rHashHexStr)
        println("03 Reference SHA1 hash is ->\t" + refHash)
        assert(rHashHexStr == refHash)
    }
  }

  test("04 Verify the 1024 bit SHA1 digital signature") {
    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+051703861611+137:20130517:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+5170386161:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130517:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TEST  REFERENCE CHAPNAR1 CHAPNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """6ECD2FBE73CD69FD30F95610B83CBDB5E7F788F9E6B0F109465EFB936CBFE2C39B8158F963083CC3F2F6B2101536029124FF60F923BA31056C4209A79F71A1D5E1F15836ED00D70F32DB67E209CBCCE9A50929E54B11CDD40F66F206BE70C0044B012F68BF0F50DD5D837D0BE9E7EB0E2871CE67033B86D95B4497196EF559C7"""
    val hashAlg = "SHA1"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "99000000114207000003_1024_identity"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("04 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("05 Verify the 2048 bit SHA1 digital signature") {
    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+052204824411+137:20130522:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+5220482441:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130522:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TEST REFERENCE CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """CCE0727DF881292DF1AC19FF23FD8848442297EE40C6269FDA1DD9900CE5FD8BDE3033FB2DF1A2426580CF26C19D6B0383F351FFCD3E1EA86E85C6840B3434186C6284829F5940D512930A4EAC6FF7AF726734B9671EACC28C19DF51A020955751D0629B6365E3573AC2D1C4C166B8E27CD5AFF4451C90958ADD70A311585C68FF04FEDDC2CE76E192320733B81D847B87F026EEB763C0F8FCB7A4E67A6D7BDD6C6262ACA6FC656DD2E966C201AE409FC56990CE132375284F55A23AAD4BBAD3985723FA6CBABB4239B5BD70BE260C9E18391D03FA6A07C8D5A68BA18D88C4464D1912CA8938628C3927B221EFD92021F5A1B042CB45D73CCD7EC5788E4BF702"""
    val hashAlg = "SHA1"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "99800000007301000021_identity"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("05 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("06 Verify the 1024 bit SHA2 digital signature - 1st Try") {

    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+062703555511+137:20130627:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+6270355551:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130627:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TESTREFERENCE2 CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """D2773D85C235174E6772F47E695143D98F4D6B58757E15F5DE0D3474140E9775149D35B3AEA81D85D2998426180764F9C866A03E3D6D3178EFDB79904D83976343951C3642C25DE13076EE356AB9D88BA4C41F9BC18D3347DF3DC6BB1DF3BFC164B31870EBE74968C0400616DC5A6F900A70906DE1AB67E0C073C37617A2DAE5"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "1024_b5c271b4689703cf3a1cf2b8fb7a85c096e07493"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("06 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("07 Verify the 2048 bit SHA2 digital signature -1st Try") {

    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+062703550711+137:20130627:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+6270355071:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130627:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TESTEREFERENCE1 CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """7FB47989BAB31F91B2AF6C8DBEC3258D9EBCB9D18B9B5BCF64EE0E16C69AAC7BF7ED1A69D775A1CE6362BE42BA0A4078DBB1AAB46A25B567B2C482EC21C7CA13CBCC9E629A6214AABA1914EF13A536EDEBCB7AA97AB42BEAB90B4C356ED85976ED3FC69D2FD22443CD1B37D277268D39DD34F81719DD06FC9210C349443FD65BDE8A6FCC6C9721F8520170F7DA71C674E31FBF4EA202009B0125E23A3322A002440A70D1BDC1833E9F5F52033D3404C5F8D29F9ED2EBF4EEA46C242182CE51D4330D9C3B54017570C80AB10521E00B2B55BF3F858FF5EB30DD546621A3A360F6420BB1FDB4758B8C9A40207BB5E0BD9FA38083EFF1284DC115EC9C04D1BD6749"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "99800000007301000021_identity"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("07 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("08 Verify the 1024 bit SHA2 digital signature - 2nd Try") {

    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+062503477611+137:20130625:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+6250347761:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130625:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TESTREFERENCE1024 CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """A4059008AF87A3B78189B9646A2F735EA85B264B07FD98DE3680A8D02373CA6D1B412A3ECA90AC7629E4556A9932B252EB74D9645FFE8A2DC0B69FC12AC8E1FB890C3B220855061D3D6AF2CE58A5EBF8E55D421284598DD6F8C078382C8638A31F538C6613F56FBDC0EF2B95CCF7EC6755E535EBC1069A81506B4274622DC544"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "1024_b5c271b4689703cf3a1cf2b8fb7a85c096e07493"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("08 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("09 Verify the 2048 bit SHA2 digital signature using 1024 bit keys") {

    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+062703550711+137:20130627:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+6270355071:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130627:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TESTEREFERENCE1 CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """7FB47989BAB31F91B2AF6C8DBEC3258D9EBCB9D18B9B5BCF64EE0E16C69AAC7BF7ED1A69D775A1CE6362BE42BA0A4078DBB1AAB46A25B567B2C482EC21C7CA13CBCC9E629A6214AABA1914EF13A536EDEBCB7AA97AB42BEAB90B4C356ED85976ED3FC69D2FD22443CD1B37D277268D39DD34F81719DD06FC9210C349443FD65BDE8A6FCC6C9721F8520170F7DA71C674E31FBF4EA202009B0125E23A3322A002440A70D1BDC1833E9F5F52033D3404C5F8D29F9ED2EBF4EEA46C242182CE51D4330D9C3B54017570C80AB10521E00B2B55BF3F858FF5EB30DD546621A3A360F6420BB1FDB4758B8C9A40207BB5E0BD9FA38083EFF1284DC115EC9C04D1BD6749"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "1024_b5c271b4689703cf3a1cf2b8fb7a85c096e07493"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("09 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(!SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("10 NOT TEST - List of Algorithms Supported by Crypto Provider") {
    import org.bouncycastle.jce.provider.BouncyCastleProvider
    import java.security.Provider.Service

    val cryptoProvider = new BouncyCastleProvider
    val services = cryptoProvider.getServices()
    var alg = List[String]()
    for (
      s <- services.toArray() if (s.asInstanceOf[Service].getType() == "Signature")
    ) {
      alg = alg ++ List(s.asInstanceOf[Service].getAlgorithm().toString())
    }
    println("10 The list of the supported Algorithms by Bouncy Castle is - \n" + alg.mkString("\n"))
    assert(1 == 1)
  }

  test("11 Verify the 1024 bit SHA2 digital signature - 20130701_TestData") {

    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+070103480311+137:20130701:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+7010348031:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130701:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TESTREFERENCE2 CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """D480734602C7672C04855A6AD7C348D86798949067890D6BBCA67F0B92578A5B482F9C25E8A1FE1DEC64232E9E032F78293D24738A5C78E602ED10BB39CAF99968C7C5B7E79E053A791F43154633134C7D1A58EAEDC83B32984E14E969C60597D8409ACC9B70E68786B7046763BD3181B94D46EDE9DB9193C60EE41E80EACF75"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "1024_b5c271b4689703cf3a1cf2b8fb7a85c096e07493"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("11 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("12 Verify the 2048 bit SHA2 digital signature - Testing 20130701_TestData") {

    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+070103475411+137:20130701:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+7010347541:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130701:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TEST REFERENCE CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """C71D1BFC57B1CE5030C8F3091AF1A6459AD3676927D4396B0016772D62B6FA4C489AD18438A2AAE8E94FB4A656FFD791390851181A0B94F1F5432B45F36332F1A199F1CD55C88DF45B938BC14C431C3C2F54CCAD07E97AD210A77EDED391B5886CDDC8DDE526B23DB621F2325388362655E152CFE538A07752AD95A0D48EDA66224F8124FCC1F2E663D0F0400AC0B771AB0DAC0B4AA428F9EB2495A05B8E9219D885A433574E79F5A34EA5B047E536F53DE12B4A6592C4425BEED60289BF69321F5503BA5212AD5AB62DBCA8E6670A76DEC0EF80CE683B00A68F02D50249351F710A2B038E21251CF7C2053DF458397A3AA11B72D19DBB1372FD64831DEA260F"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "99800000007301000021_identity"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("07 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        assert(SigUtility.verifyDigitalSignatureOfData(signedData, SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg))
    }
  }

  test("13 Test Decrypted Data using 1024 bit keys : decryptDigitalSignatureOfData") {

    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+070103480311+137:20130701:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+7010348031:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130701:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TESTREFERENCE2 CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """D480734602C7672C04855A6AD7C348D86798949067890D6BBCA67F0B92578A5B482F9C25E8A1FE1DEC64232E9E032F78293D24738A5C78E602ED10BB39CAF99968C7C5B7E79E053A791F43154633134C7D1A58EAEDC83B32984E14E969C60597D8409ACC9B70E68786B7046763BD3181B94D46EDE9DB9193C60EE41E80EACF75"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "1024_b5c271b4689703cf3a1cf2b8fb7a85c096e07493"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("13 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        val decryptedHashValue = SigUtility.decryptDigitalSignatureOfData(SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg)
        println("13 Decrypted " + hashAlg + " hash is ->\t" + decryptedHashValue)
        assert(rHashHexStr == decryptedHashValue.substring(decryptedHashValue.length() - rHashHexStr.length()))
    }
  }

  test("14 Test Decrypted Data using 2048 bit keys : decryptDigitalSignatureOfData") {
    val data = """UNH+1+PAYEXT:2:912:UN'BGM+451+070103475411+137:20130701:102+9'NAD+OY+1:160:ZZZ++TESTNAME+ADDRESS LINE ONE CAN BE UP TO 38 CH+ADDRESS LINE TWO CAN BE UP TO 38 CH+ADDRESS L+POSTCODE+GB'NAD+BE+7010347541:160:ZZZ++PAYMENT ACCOUNT+.+.+.+.+GB'FII+OR+33575985:TESTNAME+:::207929:154:133'FII+BF+83219070:PAYMENT ACCOUNT+:::207929:154:133'DTM+209:20130701:102'PAI+:::B02'MOA+7+9:1.00:GBP'FTX+PMD+++TEST REFERENCE CHAPSNAR1 CHAPSNAR2'UNS+S'MOA+3+128:1.00:GBP'UNT+13+1'"""
    val signatureData = """C71D1BFC57B1CE5030C8F3091AF1A6459AD3676927D4396B0016772D62B6FA4C489AD18438A2AAE8E94FB4A656FFD791390851181A0B94F1F5432B45F36332F1A199F1CD55C88DF45B938BC14C431C3C2F54CCAD07E97AD210A77EDED391B5886CDDC8DDE526B23DB621F2325388362655E152CFE538A07752AD95A0D48EDA66224F8124FCC1F2E663D0F0400AC0B771AB0DAC0B4AA428F9EB2495A05B8E9219D885A433574E79F5A34EA5B047E536F53DE12B4A6592C4425BEED60289BF69321F5503BA5212AD5AB62DBCA8E6670A76DEC0EF80CE683B00A68F02D50249351F710A2B038E21251CF7C2053DF458397A3AA11B72D19DBB1372FD64831DEA260F"""
    val hashAlg = "SHA256"
    val signAlg = "RSA"
    val hash = SigUtility.createHashSignatureOfData(data.getBytes(), hashAlg)

    val keyAlias = "99800000007301000021_identity"
    val key = SigUtility.fetchPublicKeyFromKeyStore(ks, keyAlias)

    (hash, key) match {
      case (Some(signedData), Some(pubKey)) =>
        val rHashHexStr = SigUtility.byteArray2HexString(signedData)
        println("14 Calcuated " + hashAlg + " hash is ->\t" + rHashHexStr)
        val decryptedHashValue = SigUtility.decryptDigitalSignatureOfData(SigUtility.hexString2ByteArray(signatureData), pubKey, signAlg)
        println("14 Decrypted " + hashAlg + " hash is ->\t" + decryptedHashValue)
        assert(rHashHexStr == decryptedHashValue.substring(decryptedHashValue.length() - rHashHexStr.length()))
    }

  }

}
