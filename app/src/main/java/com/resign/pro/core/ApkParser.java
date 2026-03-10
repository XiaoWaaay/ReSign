package com.resign.pro.core;

import android.util.Log;

import com.resign.pro.util.Logger;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * APK解析器
 * 
 * 功能：
 * - 解析AndroidManifest.xml二进制格式
 * - 读取V1/V2/V3签名信息
 * - 计算DEX文件数量
 * - 获取APK中的ABI列表
 * - 解析APK Signing Block
 */
public class ApkParser implements Closeable {

    private static final String TAG = "ApkParser";

    // APK Signing Block magic
    private static final long APK_SIG_BLOCK_MAGIC_LO = 0x20676953204B5041L; // "APK Sig "
    private static final long APK_SIG_BLOCK_MAGIC_HI = 0x3234206B636F6C42L; // "Block 42"

    // 签名方案ID
    private static final int APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a;
    private static final int APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0;
    private static final int APK_SIGNATURE_SCHEME_V31_BLOCK_ID = 0x1b93ad61;

    // AXML常量
    private static final int AXML_CHUNK_TYPE = 0x00080003;
    private static final int STRING_POOL_TYPE = 0x001C0001;
    private static final int XML_START_TAG = 0x00100102;
    private static final int XML_END_TAG = 0x00100103;
    private static final int XML_START_NAMESPACE = 0x00100100;

    private final File apkFile;
    private ZipFile zipFile;

    public ApkParser(File apkFile) throws IOException {
        this.apkFile = apkFile;
        this.zipFile = new ZipFile(apkFile);
    }

    /**
     * Manifest解析结果
     */
    public static class ManifestInfo {
        public String packageName;
        public String applicationClass;    // android:name on <application>
        public String appComponentFactory;  // android:appComponentFactory on <application>
        public int versionCode;
        public String versionName;
        public int minSdkVersion;
        public int targetSdkVersion;
        public List<String> permissions = new ArrayList<>();
        public List<String> activities = new ArrayList<>();
        public List<String> services = new ArrayList<>();
        public List<String> receivers = new ArrayList<>();
        public List<String> providers = new ArrayList<>();
    }

    /**
     * 解析AndroidManifest.xml
     */
    public ManifestInfo parseManifest() throws Exception {
        ZipEntry entry = zipFile.getEntry("AndroidManifest.xml");
        if (entry == null) {
            throw new Exception("APK中找不到AndroidManifest.xml");
        }

        ManifestInfo info = new ManifestInfo();
        byte[] data;
        try (InputStream is = zipFile.getInputStream(entry)) {
            data = readFully(is);
        }

        parseAxmlForManifest(data, info);
        return info;
    }

    /**
     * 解析二进制AXML格式的Manifest
     */
    private void parseAxmlForManifest(byte[] data, ManifestInfo info) {
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // 验证AXML头
        int magic = buf.getInt(0);
        if (magic != AXML_CHUNK_TYPE) {
            Logger.w(TAG, "非标准AXML格式: 0x" + Integer.toHexString(magic));
        }

        // 解析字符串池
        int stringPoolOffset = 8;
        buf.position(stringPoolOffset);
        int spType = buf.getInt();
        int spSize = buf.getInt();
        int stringCount = buf.getInt();
        int styleCount = buf.getInt();
        int spFlags = buf.getInt();
        int stringsStart = buf.getInt();
        int stylesStart = buf.getInt();

        // 读取字符串偏移表
        int[] stringOffsets = new int[stringCount];
        for (int i = 0; i < stringCount; i++) {
            stringOffsets[i] = buf.getInt();
        }

        // 读取字符串内容
        boolean isUtf8 = (spFlags & (1 << 8)) != 0;
        String[] strings = new String[stringCount];
        int strDataStart = stringPoolOffset + 8 + 20 + stringCount * 4 + styleCount * 4;
        // 使用stringsStart的实际偏移
        int actualStringsStart = stringPoolOffset + 8 + stringsStart;

        for (int i = 0; i < stringCount; i++) {
            int offset = actualStringsStart + stringOffsets[i];
            try {
                if (isUtf8) {
                    strings[i] = readUtf8String(data, offset);
                } else {
                    strings[i] = readUtf16String(data, offset);
                }
            } catch (Exception e) {
                strings[i] = "";
            }
        }

        // 遍历XML元素，提取关键属性
        int pos = stringPoolOffset + spSize;
        String currentTag = null;

        while (pos < data.length - 8) {
            buf.position(pos);
            int chunkType = buf.getInt();
            int chunkSize = buf.getInt();

            if (chunkSize < 8) break;

            if (chunkType == XML_START_TAG) {
                if (pos + 28 > data.length) break;
                buf.position(pos + 8);
                int lineNumber = buf.getInt();
                int comment = buf.getInt();
                int nsIdx = buf.getInt();
                int nameIdx = buf.getInt();
                int attrStart = buf.getShort() & 0xFFFF;
                int attrSize = buf.getShort() & 0xFFFF;
                int attrCount = buf.getShort() & 0xFFFF;

                if (nameIdx >= 0 && nameIdx < strings.length) {
                    currentTag = strings[nameIdx];
                }

                // 解析属性
                int attrOffset = pos + 8 + 20 + attrStart - 8;
                for (int i = 0; i < attrCount; i++) {
                    int aPos = attrOffset + i * 20; // 每个属性20字节
                    if (aPos + 20 > data.length) break;

                    buf.position(aPos);
                    int attrNsIdx = buf.getInt();
                    int attrNameIdx = buf.getInt();
                    int attrValueStr = buf.getInt();
                    int attrType = buf.getShort() & 0xFFFF;
                    int attrTypeValue = buf.getShort() & 0xFFFF;
                    int attrData = buf.getInt();

                    String attrName = (attrNameIdx >= 0 && attrNameIdx < strings.length) ?
                            strings[attrNameIdx] : "";
                    String attrValue = (attrValueStr >= 0 && attrValueStr < strings.length) ?
                            strings[attrValueStr] : "";

                    // 根据tag和属性名提取信息
                    if ("manifest".equals(currentTag)) {
                        if ("package".equals(attrName)) {
                            info.packageName = attrValue;
                        } else if ("versionCode".equals(attrName)) {
                            info.versionCode = attrData;
                        } else if ("versionName".equals(attrName)) {
                            info.versionName = attrValue;
                        }
                    } else if ("application".equals(currentTag)) {
                        if ("name".equals(attrName)) {
                            info.applicationClass = attrValue;
                        } else if ("appComponentFactory".equals(attrName)) {
                            info.appComponentFactory = attrValue;
                        }
                    } else if ("uses-sdk".equals(currentTag)) {
                        if ("minSdkVersion".equals(attrName)) {
                            info.minSdkVersion = attrData;
                        } else if ("targetSdkVersion".equals(attrName)) {
                            info.targetSdkVersion = attrData;
                        }
                    } else if ("activity".equals(currentTag) && "name".equals(attrName)) {
                        info.activities.add(attrValue);
                    } else if ("service".equals(currentTag) && "name".equals(attrName)) {
                        info.services.add(attrValue);
                    } else if ("receiver".equals(currentTag) && "name".equals(attrName)) {
                        info.receivers.add(attrValue);
                    } else if ("provider".equals(currentTag) && "name".equals(attrName)) {
                        info.providers.add(attrValue);
                    } else if ("uses-permission".equals(currentTag) && "name".equals(attrName)) {
                        info.permissions.add(attrValue);
                    }
                }
            }

            pos += chunkSize;
        }

        Logger.i(TAG, "Manifest解析完成: pkg=" + info.packageName
                + ", app=" + info.applicationClass);
    }

    /**
     * 统计APK中的DEX文件数量
     */
    public int countDexFiles() {
        int count = 0;
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            if (name.matches("classes\\d*\\.dex")) {
                count++;
            }
        }
        return count;
    }

    /**
     * 获取APK中包含的ABI列表
     */
    public String[] getAbis() {
        Set<String> abis = new HashSet<>();
        Enumeration<? extends ZipEntry> entries = zipFile.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            String name = entry.getName();
            if (name.startsWith("lib/") && name.endsWith(".so")) {
                // 格式: lib/<abi>/xxx.so
                String[] parts = name.split("/");
                if (parts.length >= 2) {
                    abis.add(parts[1]);
                }
            }
        }
        return abis.toArray(new String[0]);
    }

    /**
     * 检查APK是否存在APK Signing Block
     */
    public boolean hasSigningBlock() {
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            return findSigningBlock(raf) != null;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 查找APK Signing Block位置
     * @return [blockOffset, blockSize] 或 null
     */
    public static long[] findSigningBlock(RandomAccessFile raf) throws IOException {
        // ZIP End of Central Directory在文件末尾
        long fileSize = raf.length();
        if (fileSize < 22) return null;

        // 查找EOCD
        long eocdOffset = -1;
        for (long i = fileSize - 22; i >= Math.max(0, fileSize - 65557); i--) {
            raf.seek(i);
            if (raf.readInt() == 0x06054b50) { // EOCD signature
                eocdOffset = i;
                break;
            }
        }
        if (eocdOffset == -1) return null;

        // 读取Central Directory偏移
        raf.seek(eocdOffset + 16);
        long cdOffset = Integer.toUnsignedLong(readLittleEndianInt(raf));

        // Signing Block位于Central Directory之前
        if (cdOffset < 24) return null;

        // 读取Signing Block尾部的size和magic
        raf.seek(cdOffset - 24);
        long blockSizeInFooter = readLittleEndianLong(raf);
        long magicLo = readLittleEndianLong(raf);
        long magicHi = readLittleEndianLong(raf);

        if (magicLo != APK_SIG_BLOCK_MAGIC_LO || magicHi != APK_SIG_BLOCK_MAGIC_HI) {
            return null;
        }

        // Signing Block起始位置
        long blockOffset = cdOffset - blockSizeInFooter - 8;
        if (blockOffset < 0) return null;

        return new long[]{blockOffset, blockSizeInFooter + 8};
    }

    /**
     * 提取APK Signing Block中的指定ID数据
     */
    public static byte[] getSigningBlockEntry(RandomAccessFile raf, int blockId) throws IOException {
        long[] blockInfo = findSigningBlock(raf);
        if (blockInfo == null) return null;

        long blockOffset = blockInfo[0];
        long blockSize = blockInfo[1];

        // 读取整个Signing Block
        raf.seek(blockOffset);
        long sizeInHeader = readLittleEndianLong(raf);
        long pairsEnd = blockOffset + 8 + sizeInHeader - 24; // 减去footer的24字节
        long pos = blockOffset + 8;

        while (pos < pairsEnd) {
            raf.seek(pos);
            long pairSize = readLittleEndianLong(raf);
            if (pairSize < 4) break;
            int id = readLittleEndianInt(raf);

            if (id == blockId) {
                byte[] data = new byte[(int) (pairSize - 4)];
                raf.readFully(data);
                return data;
            }

            pos += 8 + pairSize;
        }

        return null;
    }

    // ========== 工具方法 ==========

    private String readUtf8String(byte[] data, int offset) {
        if (offset >= data.length) return "";
        // UTF-8编码：第一字节是字符数（可能是2字节编码），后面是字节数
        int charLen = data[offset] & 0xFF;
        if ((charLen & 0x80) != 0) {
            charLen = ((charLen & 0x7F) << 8) | (data[offset + 1] & 0xFF);
            offset++;
        }
        offset++;

        int byteLen = data[offset] & 0xFF;
        if ((byteLen & 0x80) != 0) {
            byteLen = ((byteLen & 0x7F) << 8) | (data[offset + 1] & 0xFF);
            offset++;
        }
        offset++;

        if (offset + byteLen > data.length) byteLen = data.length - offset;
        return new String(data, offset, byteLen);
    }

    private String readUtf16String(byte[] data, int offset) {
        if (offset + 2 > data.length) return "";
        int charLen = (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8);
        if ((charLen & 0x8000) != 0) {
            charLen = ((charLen & 0x7FFF) << 16) |
                    ((data[offset + 2] & 0xFF) | ((data[offset + 3] & 0xFF) << 8));
            offset += 4;
        } else {
            offset += 2;
        }
        int byteLen = charLen * 2;
        if (offset + byteLen > data.length) byteLen = data.length - offset;
        return new String(data, offset, byteLen, java.nio.charset.StandardCharsets.UTF_16LE);
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

    private static int readLittleEndianInt(RandomAccessFile raf) throws IOException {
        byte[] buf = new byte[4];
        raf.readFully(buf);
        return (buf[0] & 0xFF) | ((buf[1] & 0xFF) << 8)
                | ((buf[2] & 0xFF) << 16) | ((buf[3] & 0xFF) << 24);
    }

    private static long readLittleEndianLong(RandomAccessFile raf) throws IOException {
        byte[] buf = new byte[8];
        raf.readFully(buf);
        long lo = (buf[0] & 0xFFL) | ((buf[1] & 0xFFL) << 8)
                | ((buf[2] & 0xFFL) << 16) | ((buf[3] & 0xFFL) << 24);
        long hi = (buf[4] & 0xFFL) | ((buf[5] & 0xFFL) << 8)
                | ((buf[6] & 0xFFL) << 16) | ((buf[7] & 0xFFL) << 24);
        return lo | (hi << 32);
    }

    @Override
    public void close() throws IOException {
        if (zipFile != null) {
            zipFile.close();
            zipFile = null;
        }
    }
}
