package com.resign.pro.core;

import android.content.Context;

import com.resign.pro.util.Logger;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.Enumeration;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * APK签名器
 * 
 * 支持V1 (JAR) 签名方案
 * V2/V3签名通过ApkSigningBlock保留实现
 * 
 * V1签名流程：
 * 1. 对APK中每个文件计算SHA-256摘要，写入META-INF/MANIFEST.MF
 * 2. 对MANIFEST.MF计算摘要，连同各文件摘要写入META-INF/<alias>.SF
 * 3. 使用私钥对SF文件签名，写入META-INF/<alias>.RSA
 */
public class ApkSigner {

    private static final String TAG = "ApkSigner";

    private static final String CERT_ALIAS = "resignpro";
    private static final String STORE_PASS = "resign123";
    private static final String KEY_PASS = "resign123";
    private static final String SIG_FILE_NAME = "CERT";

    /**
     * 对APK进行V1签名
     * 使用内置的测试签名密钥
     */
    public static void signV1(File apkFile, Context context) throws Exception {
        // 获取或生成签名密钥
        KeyStore keyStore = getOrCreateKeyStore(context);
        PrivateKey privateKey = (PrivateKey) keyStore.getKey(CERT_ALIAS, KEY_PASS.toCharArray());
        Certificate cert = keyStore.getCertificate(CERT_ALIAS);

        if (privateKey == null || cert == null) {
            throw new Exception("签名密钥获取失败");
        }

        // 创建临时输出文件
        File tmpFile = new File(apkFile.getParent(), apkFile.getName() + ".signing.tmp");

        try {
            // 读取APK内容，计算摘要，生成签名文件
            performV1Sign(apkFile, tmpFile, privateKey, (X509Certificate) cert);

            // 替换原文件
            if (!apkFile.delete()) {
                throw new IOException("无法删除原APK文件");
            }
            if (!tmpFile.renameTo(apkFile)) {
                throw new IOException("无法重命名签名后的APK");
            }

            Logger.i(TAG, "V1签名完成: " + apkFile.getAbsolutePath());
        } catch (Exception e) {
            tmpFile.delete();
            throw e;
        }
    }

    /**
     * 执行V1签名
     */
    private static void performV1Sign(File inputApk, File outputApk,
                                       PrivateKey privateKey, X509Certificate cert) throws Exception {
        // 构建MANIFEST.MF
        Manifest manifest = new Manifest();
        Attributes mainAttrs = manifest.getMainAttributes();
        mainAttrs.putValue("Manifest-Version", "1.0");
        mainAttrs.putValue("Created-By", "1.0 (ReSignPro)");

        try (ZipFile zipFile = new ZipFile(inputApk)) {
            // 计算每个条目的摘要
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                // 跳过META-INF中的签名文件
                if (name.startsWith("META-INF/")) {
                    String upper = name.toUpperCase();
                    if (upper.endsWith(".SF") || upper.endsWith(".RSA")
                            || upper.endsWith(".DSA") || upper.endsWith(".EC")
                            || upper.equals("META-INF/MANIFEST.MF")) {
                        continue;
                    }
                }

                if (entry.isDirectory()) continue;

                // 计算SHA-256摘要
                byte[] digest;
                try (InputStream is = zipFile.getInputStream(entry)) {
                    digest = computeSHA256(is);
                }

                Attributes attrs = new Attributes();
                attrs.putValue("SHA-256-Digest",
                        android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP));
                manifest.getEntries().put(name, attrs);
            }

            // 构建SF (Signature File)
            byte[] manifestBytes = manifestToBytes(manifest);
            byte[] manifestDigest = MessageDigest.getInstance("SHA-256").digest(manifestBytes);

            StringBuilder sfBuilder = new StringBuilder();
            sfBuilder.append("Signature-Version: 1.0\r\n");
            sfBuilder.append("Created-By: 1.0 (ReSignPro)\r\n");
            sfBuilder.append("SHA-256-Digest-Manifest: ");
            sfBuilder.append(android.util.Base64.encodeToString(manifestDigest,
                    android.util.Base64.NO_WRAP));
            sfBuilder.append("\r\n\r\n");

            // 每个条目在SF中也有摘要
            for (java.util.Map.Entry<String, Attributes> me : manifest.getEntries().entrySet()) {
                String entryBlock = "Name: " + me.getKey() + "\r\n"
                        + "SHA-256-Digest: " + me.getValue().getValue("SHA-256-Digest") + "\r\n\r\n";
                byte[] blockDigest = MessageDigest.getInstance("SHA-256")
                        .digest(entryBlock.getBytes("UTF-8"));
                sfBuilder.append("Name: ").append(me.getKey()).append("\r\n");
                sfBuilder.append("SHA-256-Digest: ");
                sfBuilder.append(android.util.Base64.encodeToString(blockDigest,
                        android.util.Base64.NO_WRAP));
                sfBuilder.append("\r\n\r\n");
            }

            byte[] sfBytes = sfBuilder.toString().getBytes("UTF-8");

            // 生成RSA签名
            java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(sfBytes);
            byte[] signatureBytes = sig.sign();

            // 构建PKCS7 SignedData结构
            byte[] pkcs7 = buildSimplePKCS7(cert, signatureBytes, sfBytes);

            // 写入输出APK
            try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(outputApk))) {
                zos.setMethod(ZipOutputStream.STORED);

                // 先写META-INF签名文件
                writeStoredEntry(zos, "META-INF/MANIFEST.MF", manifestBytes);
                writeStoredEntry(zos, "META-INF/" + SIG_FILE_NAME + ".SF", sfBytes);
                writeStoredEntry(zos, "META-INF/" + SIG_FILE_NAME + ".RSA", pkcs7);

                // 再写原始文件
                entries = zipFile.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String name = entry.getName();

                    // 跳过旧的签名文件
                    if (name.startsWith("META-INF/")) {
                        String upper = name.toUpperCase();
                        if (upper.endsWith(".SF") || upper.endsWith(".RSA")
                                || upper.endsWith(".DSA") || upper.endsWith(".EC")
                                || upper.equals("META-INF/MANIFEST.MF")) {
                            continue;
                        }
                    }

                    try (InputStream is = zipFile.getInputStream(entry)) {
                        byte[] data = readFully(is);
                        ZipEntry newEntry = new ZipEntry(name);
                        if (entry.getMethod() == ZipEntry.STORED) {
                            newEntry.setMethod(ZipEntry.STORED);
                            newEntry.setSize(data.length);
                            newEntry.setCompressedSize(data.length);
                            newEntry.setCrc(computeCRC32(data));
                        } else {
                            newEntry.setMethod(ZipEntry.DEFLATED);
                        }
                        zos.putNextEntry(newEntry);
                        zos.write(data);
                        zos.closeEntry();
                    }
                }
            }
        }
    }

    /**
     * 获取或创建签名KeyStore
     */
    private static KeyStore getOrCreateKeyStore(Context context) throws Exception {
        File ksFile = new File(context.getFilesDir(), "resign_pro_keystore.bks");

        KeyStore ks = KeyStore.getInstance("BKS");

        if (ksFile.exists()) {
            try (FileInputStream fis = new FileInputStream(ksFile)) {
                ks.load(fis, STORE_PASS.toCharArray());
                if (ks.containsAlias(CERT_ALIAS)) {
                    return ks;
                }
            } catch (Exception e) {
                Logger.w(TAG, "加载已有KeyStore失败，将重新创建");
            }
        }

        // 生成新的RSA密钥对
        ks.load(null, null);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // 自签名证书 —— 使用简化方式
        X509Certificate selfCert = generateSelfSignedCert(kp);

        ks.setKeyEntry(CERT_ALIAS, kp.getPrivate(), KEY_PASS.toCharArray(),
                new Certificate[]{selfCert});

        try (FileOutputStream fos = new FileOutputStream(ksFile)) {
            ks.store(fos, STORE_PASS.toCharArray());
        }

        Logger.i(TAG, "签名KeyStore创建完成");
        return ks;
    }

    /**
     * 生成自签名X509证书
     */
    private static X509Certificate generateSelfSignedCert(KeyPair keyPair) throws Exception {
        // 使用Android内置的Bouncy Castle/Conscrypt来创建自签名证书
        // 这是一个简化实现——实际上Android环境可以通过KeyPairGenerator直接生成
        
        // 构建简单的X.509 v3自签名证书（使用DER编码）
        // Subject: CN=ReSignPro
        byte[] pubKeyEncoded = keyPair.getPublic().getEncoded();
        
        // 使用java.security的Signature来签名TBS证书
        // 简化起见，这里使用Android KeyStore API或手动构造
        // 实际项目中建议使用Bouncy Castle的X509v3CertificateBuilder
        
        // 方案：直接使用android.security.keystore或手工DER编码
        // 这里采用最简单的方式——调用系统的自签名功能
        String dn = "CN=ReSignPro, O=ReSignPro, C=CN";
        long validity = 365L * 24 * 60 * 60 * 1000 * 30; // 30年
        
        // 使用反射调用Android内部的CertificateBuilder（如果可用）
        // 或者使用手动DER编码构建证书
        return buildSelfSignedCertManual(keyPair, dn, validity);
    }

    /**
     * 手动构建自签名证书的DER编码
     */
    private static X509Certificate buildSelfSignedCertManual(KeyPair kp, String dn, long validityMs) throws Exception {
        // 使用简化的ASN.1 DER编码创建X.509证书
        Date now = new Date();
        Date expiry = new Date(now.getTime() + validityMs);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        // 通过反射使用sun.security.x509或Bouncy Castle
        // Android上优先尝试 android.security 相关API
        try {
            // 尝试使用Bouncy Castle（Android内置）
            Class<?> bcClass = Class.forName("org.bouncycastle.x509.X509V3CertificateGenerator");
            Object gen = bcClass.newInstance();
            
            Class<?> x500Class = Class.forName("javax.security.auth.x500.X500Principal");
            Object principal = x500Class.getConstructor(String.class).newInstance(dn);
            
            bcClass.getMethod("setSerialNumber", BigInteger.class).invoke(gen, serial);
            bcClass.getMethod("setNotBefore", Date.class).invoke(gen, now);
            bcClass.getMethod("setNotAfter", Date.class).invoke(gen, expiry);
            bcClass.getMethod("setSubjectDN", x500Class).invoke(gen, principal);
            bcClass.getMethod("setIssuerDN", x500Class).invoke(gen, principal);
            bcClass.getMethod("setPublicKey", java.security.PublicKey.class).invoke(gen, kp.getPublic());
            bcClass.getMethod("setSignatureAlgorithm", String.class).invoke(gen, "SHA256WithRSAEncryption");

            return (X509Certificate) bcClass.getMethod("generate", PrivateKey.class).invoke(gen, kp.getPrivate());
        } catch (Exception e) {
            Logger.w(TAG, "BouncyCastle方式失败，使用备用方案: " + e.getMessage());
        }

        // 备用：直接使用KeyStore API生成一个临时证书
        // 通过Android KeyStore生成密钥并导出证书
        // 这里使用一个硬编码的测试证书作为兜底
        return createFallbackCert(kp);
    }

    /**
     * 兜底：使用简单DER编码创建证书
     */
    private static X509Certificate createFallbackCert(KeyPair kp) throws Exception {
        // 极简自签名证书：使用手写DER
        // 实际建议在构建时用keytool/openssl预生成keystore打包到assets中
        
        // 生成一个minimal X.509 cert via java.security
        // Use the Signature class to sign TBSCertificate manually
        java.security.Signature sig = java.security.Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());

        // Build TBSCertificate DER (simplified)
        byte[] subjectDN = derEncodeRDN("ReSignPro");
        byte[] pubKeyInfo = kp.getPublic().getEncoded();
        byte[] serialNum = derEncodeInteger(BigInteger.valueOf(System.currentTimeMillis()));
        byte[] validity = derEncodeValidity(new Date(), new Date(System.currentTimeMillis() + 30L * 365 * 86400000));
        byte[] sigAlgId = derEncodeSHA256WithRSA();

        // TBSCertificate sequence
        byte[] tbs = derSequence(
                derExplicit(0, derEncodeInteger(BigInteger.valueOf(2))), // version v3
                serialNum,
                sigAlgId,
                subjectDN, // issuer = subject (self-signed)
                validity,
                subjectDN, // subject
                pubKeyInfo
        );

        sig.update(tbs);
        byte[] signature = sig.sign();

        // Full certificate
        byte[] cert = derSequence(
                tbs,
                sigAlgId,
                derBitString(signature)
        );

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(cert));
    }

    // ========== 简化的PKCS7构建 ==========

    private static byte[] buildSimplePKCS7(X509Certificate cert, byte[] signature, byte[] content) throws Exception {
        // 构建简化的PKCS#7 SignedData结构
        // 实际签名工具会构建完整的ASN.1 DER编码
        // 这里使用cert.getEncoded()和signature直接拼装

        byte[] certEncoded = cert.getEncoded();
        
        // PKCS7 SignedData (simplified DER)
        byte[] digestAlgId = derSequence(derOID(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 1})); // SHA-256
        byte[] digestAlgSet = derSet(digestAlgId);
        byte[] contentInfo = derSequence(derOID(new int[]{1, 2, 840, 113549, 1, 7, 1})); // data
        byte[] certSet = derExplicit(0, certEncoded);

        // SignerInfo
        byte[] signerInfo = derSequence(
                derEncodeInteger(BigInteger.ONE), // version
                derSequence( // issuerAndSerialNumber
                        extractIssuerDN(certEncoded),
                        derEncodeInteger(cert.getSerialNumber())
                ),
                digestAlgId,
                derSequence(derOID(new int[]{1, 2, 840, 113549, 1, 1, 11})), // sha256WithRSA
                derOctetString(signature)
        );

        byte[] signedData = derSequence(
                derEncodeInteger(BigInteger.ONE), // version
                digestAlgSet,
                contentInfo,
                certSet,
                derSet(signerInfo)
        );

        return derSequence(
                derOID(new int[]{1, 2, 840, 113549, 1, 7, 2}), // signedData
                derExplicit(0, signedData)
        );
    }

    // ========== DER编码辅助方法 ==========

    private static byte[] derSequence(byte[]... contents) {
        return derWrap(0x30, contents);
    }

    private static byte[] derSet(byte[]... contents) {
        return derWrap(0x31, contents);
    }

    private static byte[] derWrap(int tag, byte[]... contents) {
        int totalLen = 0;
        for (byte[] c : contents) totalLen += c.length;
        byte[] lenBytes = derLength(totalLen);
        byte[] result = new byte[1 + lenBytes.length + totalLen];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        int pos = 1 + lenBytes.length;
        for (byte[] c : contents) {
            System.arraycopy(c, 0, result, pos, c.length);
            pos += c.length;
        }
        return result;
    }

    private static byte[] derExplicit(int tagNum, byte[] content) {
        int tag = 0xA0 | tagNum;
        byte[] lenBytes = derLength(content.length);
        byte[] result = new byte[1 + lenBytes.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(content, 0, result, 1 + lenBytes.length, content.length);
        return result;
    }

    private static byte[] derLength(int len) {
        if (len < 128) return new byte[]{(byte) len};
        if (len < 256) return new byte[]{(byte) 0x81, (byte) len};
        return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) len};
    }

    private static byte[] derEncodeInteger(BigInteger value) {
        byte[] vBytes = value.toByteArray();
        byte[] lenBytes = derLength(vBytes.length);
        byte[] result = new byte[1 + lenBytes.length + vBytes.length];
        result[0] = 0x02; // INTEGER tag
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(vBytes, 0, result, 1 + lenBytes.length, vBytes.length);
        return result;
    }

    private static byte[] derOctetString(byte[] data) {
        byte[] lenBytes = derLength(data.length);
        byte[] result = new byte[1 + lenBytes.length + data.length];
        result[0] = 0x04;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(data, 0, result, 1 + lenBytes.length, data.length);
        return result;
    }

    private static byte[] derBitString(byte[] data) {
        byte[] lenBytes = derLength(data.length + 1);
        byte[] result = new byte[1 + lenBytes.length + 1 + data.length];
        result[0] = 0x03;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        result[1 + lenBytes.length] = 0x00; // unused bits
        System.arraycopy(data, 0, result, 2 + lenBytes.length, data.length);
        return result;
    }

    private static byte[] derOID(int[] components) {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        bos.write(components[0] * 40 + components[1]);
        for (int i = 2; i < components.length; i++) {
            int val = components[i];
            if (val < 128) {
                bos.write(val);
            } else {
                byte[] encoded = new byte[5];
                int pos = 4;
                encoded[pos] = (byte) (val & 0x7F);
                val >>= 7;
                while (val > 0) {
                    encoded[--pos] = (byte) (0x80 | (val & 0x7F));
                    val >>= 7;
                }
                bos.write(encoded, pos, 5 - pos);
            }
        }
        byte[] oidData = bos.toByteArray();
        byte[] lenBytes = derLength(oidData.length);
        byte[] result = new byte[1 + lenBytes.length + oidData.length];
        result[0] = 0x06;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(oidData, 0, result, 1 + lenBytes.length, oidData.length);
        return result;
    }

    private static byte[] derEncodeRDN(String cn) {
        byte[] cnBytes = cn.getBytes();
        byte[] cnValue = new byte[2 + cnBytes.length];
        cnValue[0] = 0x0C; // UTF8String
        cnValue[1] = (byte) cnBytes.length;
        System.arraycopy(cnBytes, 0, cnValue, 2, cnBytes.length);

        byte[] cnOid = derOID(new int[]{2, 5, 4, 3}); // CN
        byte[] atv = derSequence(cnOid, cnValue);
        byte[] rdnSet = derSet(atv);
        return derSequence(rdnSet);
    }

    private static byte[] derEncodeSHA256WithRSA() {
        return derSequence(
                derOID(new int[]{1, 2, 840, 113549, 1, 1, 11}),
                new byte[]{0x05, 0x00} // NULL
        );
    }

    private static byte[] derEncodeValidity(Date from, Date to) {
        return derSequence(derEncodeUTCTime(from), derEncodeUTCTime(to));
    }

    private static byte[] derEncodeUTCTime(Date date) {
        java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat("yyMMddHHmmss'Z'");
        sdf.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        byte[] timeBytes = sdf.format(date).getBytes();
        byte[] result = new byte[2 + timeBytes.length];
        result[0] = 0x17; // UTCTime
        result[1] = (byte) timeBytes.length;
        System.arraycopy(timeBytes, 0, result, 2, timeBytes.length);
        return result;
    }

    private static byte[] extractIssuerDN(byte[] certDER) {
        // 从证书DER中提取issuer字段（简化：返回一个dummy）
        return derEncodeRDN("ReSignPro");
    }

    private static byte[] computeSHA256(InputStream is) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) != -1) {
            md.update(buf, 0, n);
        }
        return md.digest();
    }

    private static long computeCRC32(byte[] data) {
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        return crc.getValue();
    }

    private static byte[] manifestToBytes(Manifest manifest) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        manifest.write(bos);
        return bos.toByteArray();
    }

    private static void writeStoredEntry(ZipOutputStream zos, String name, byte[] data) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        entry.setMethod(ZipEntry.STORED);
        entry.setSize(data.length);
        entry.setCompressedSize(data.length);
        java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        entry.setCrc(crc.getValue());
        zos.putNextEntry(entry);
        zos.write(data);
        zos.closeEntry();
    }

    private static byte[] readFully(InputStream is) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
