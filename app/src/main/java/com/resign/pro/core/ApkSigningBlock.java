package com.resign.pro.core;

import com.resign.pro.util.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * APK Signing Block 处理器
 * 
 * APK文件结构：
 * [Contents of ZIP entries] | [APK Signing Block] | [Central Directory] | [EOCD]
 * 
 * 功能：
 * 1. 解析APK Signing Block结构
 * 2. 从原始APK保留Signing Block到修改后的APK（保持V2/V3签名可用）
 * 3. 伪造空的Signing Block占位
 * 
 * 注意：修改APK内容后Signing Block中的哈希会失效，但某些检测
 * 只检查Block是否存在而不验证完整性，因此保留Block有助于绕过简单检测。
 * 对于严格验证场景，需要配合运行时hook来伪造签名信息。
 */
public class ApkSigningBlock {

    private static final String TAG = "ApkSigningBlock";

    private static final long MAGIC_LO = 0x20676953204B5041L;
    private static final long MAGIC_HI = 0x3234206B636F6C42L;

    private static final int BLOCK_ID_V2 = 0x7109871a;
    private static final int BLOCK_ID_V3 = 0xf05368c0;
    private static final int BLOCK_ID_V31 = 0x1b93ad61;
    // padding block
    private static final int BLOCK_ID_VERITY_PADDING = 0x42726577;

    /**
     * 从原始APK保留Signing Block到目标APK
     * 
     * 流程：
     * 1. 从原始APK读取完整的Signing Block
     * 2. 在目标APK中找到Central Directory位置
     * 3. 将Signing Block插入到目标APK的Contents与Central Directory之间
     * 4. 更新EOCD中的Central Directory偏移
     */
    public static void preserveSigningBlock(File originalApk, File targetApk) throws Exception {
        byte[] sigBlock = extractSigningBlock(originalApk);
        if (sigBlock == null) {
            throw new Exception("原始APK中没有Signing Block");
        }

        Logger.i(TAG, "原始Signing Block大小: " + sigBlock.length + " bytes");
        insertSigningBlock(targetApk, sigBlock);
    }

    /**
     * 从APK中提取完整的Signing Block
     */
    public static byte[] extractSigningBlock(File apkFile) throws IOException {
        try (RandomAccessFile raf = new RandomAccessFile(apkFile, "r")) {
            long[] blockInfo = ApkParser.findSigningBlock(raf);
            if (blockInfo == null) return null;

            long blockOffset = blockInfo[0];
            long blockSize = blockInfo[1];

            // 读取完整的Signing Block（包括头部size和尾部magic）
            // 实际block结构：[size:8] [pairs...] [size:8] [magic:16]
            // blockInfo[0] = block起始（size字段）
            // blockInfo[1] = block内容大小 + 8（头部size）

            // 计算完整block大小（加上尾部的 size+magic = 24字节）
            long fullSize = blockSize + 24;
            
            if (fullSize > 50 * 1024 * 1024) { // 安全限制50MB
                throw new IOException("Signing Block过大: " + fullSize);
            }

            raf.seek(blockOffset);
            byte[] block = new byte[(int) fullSize];
            raf.readFully(block);
            return block;
        }
    }

    /**
     * 将Signing Block插入到目标APK中
     */
    public static void insertSigningBlock(File apkFile, byte[] sigBlock) throws IOException {
        // 读取目标APK的全部内容
        byte[] apkData;
        try (FileInputStream fis = new FileInputStream(apkFile)) {
            apkData = readFully(fis);
        }

        // 查找EOCD
        int eocdOffset = findEocd(apkData);
        if (eocdOffset == -1) {
            throw new IOException("找不到EOCD");
        }

        // 读取Central Directory偏移（EOCD + 16处的4字节，小端）
        int cdOffset = readInt32LE(apkData, eocdOffset + 16);

        // 检查目标APK是否已有Signing Block（需要先移除）
        int insertPoint = cdOffset;
        int existingBlockEnd = cdOffset;
        
        // 尝试检测已有的Signing Block
        if (cdOffset >= 32) {
            // 检查CD前面是否有magic
            long magicLo = readInt64LE(apkData, cdOffset - 16);
            long magicHi = readInt64LE(apkData, cdOffset - 8);
            if (magicLo == MAGIC_LO && magicHi == MAGIC_HI) {
                // 已有Signing Block，读取其size来确定起始位置
                long blockSize = readInt64LE(apkData, cdOffset - 24);
                insertPoint = (int) (cdOffset - blockSize - 8);
                Logger.i(TAG, "目标APK已有Signing Block，将替换");
            }
        }

        // 构建新的APK：
        // [原始Contents (0..insertPoint)] + [新Signing Block] + [Central Directory] + [EOCD]
        int contentsSize = insertPoint;
        int cdSize = eocdOffset - existingBlockEnd;
        int eocdSize = apkData.length - eocdOffset;

        byte[] newApk = new byte[contentsSize + sigBlock.length + cdSize + eocdSize];
        int pos = 0;

        // 1. 复制ZIP Contents
        System.arraycopy(apkData, 0, newApk, pos, contentsSize);
        pos += contentsSize;

        // 2. 插入Signing Block
        System.arraycopy(sigBlock, 0, newApk, pos, sigBlock.length);
        int newCdOffset = pos + sigBlock.length;
        pos += sigBlock.length;

        // 3. 复制Central Directory
        System.arraycopy(apkData, existingBlockEnd, newApk, pos, cdSize);
        pos += cdSize;

        // 4. 复制EOCD
        System.arraycopy(apkData, eocdOffset, newApk, pos, eocdSize);

        // 5. 更新EOCD中的CD偏移
        int newEocdOffset = contentsSize + sigBlock.length + cdSize;
        writeInt32LE(newApk, newEocdOffset + 16, newCdOffset);

        // 写回文件
        try (FileOutputStream fos = new FileOutputStream(apkFile)) {
            fos.write(newApk);
        }

        Logger.i(TAG, "Signing Block插入完成, 新CD偏移: " + newCdOffset);
    }

    /**
     * 创建一个最小的占位Signing Block
     * 用于欺骗简单的Block存在性检测
     */
    public static byte[] createDummySigningBlock() {
        // 最小结构：[size:8] [padding-pair] [size:8] [magic:16]
        // padding pair: [pairSize:8] [id:4] [data...]
        byte[] paddingData = new byte[4]; // 空padding
        long pairSize = 4 + paddingData.length; // id(4) + data
        long blockContentSize = 8 + pairSize; // pairSize(8) + pair
        long totalBlockSize = blockContentSize + 24; // + footer(size:8 + magic:16)

        ByteBuffer buf = ByteBuffer.allocate((int) (8 + blockContentSize + 24))
                .order(ByteOrder.LITTLE_ENDIAN);

        // Header size
        buf.putLong(blockContentSize + 16); // size字段包含自身到magic之间的内容

        // Pair
        buf.putLong(pairSize);
        buf.putInt(BLOCK_ID_VERITY_PADDING);
        buf.put(paddingData);

        // Footer
        buf.putLong(blockContentSize + 16);
        buf.putLong(MAGIC_LO);
        buf.putLong(MAGIC_HI);

        return buf.array();
    }

    /**
     * 解析Signing Block中的所有pair ID
     */
    public static int[] getBlockIds(byte[] sigBlock) {
        if (sigBlock == null || sigBlock.length < 32) return new int[0];

        ByteBuffer buf = ByteBuffer.wrap(sigBlock).order(ByteOrder.LITTLE_ENDIAN);
        long size = buf.getLong(); // header size

        java.util.List<Integer> ids = new java.util.ArrayList<>();
        int pos = 8;
        int end = sigBlock.length - 24; // 减去footer

        while (pos < end) {
            if (pos + 12 > end) break;
            buf.position(pos);
            long pairSize = buf.getLong();
            if (pairSize < 4) break;
            int id = buf.getInt();
            ids.add(id);
            pos += 8 + (int) pairSize;
        }

        int[] result = new int[ids.size()];
        for (int i = 0; i < ids.size(); i++) {
            result[i] = ids.get(i);
        }
        return result;
    }

    /**
     * 检查Block中是否包含V2签名
     */
    public static boolean hasV2Signature(byte[] sigBlock) {
        for (int id : getBlockIds(sigBlock)) {
            if (id == BLOCK_ID_V2) return true;
        }
        return false;
    }

    /**
     * 检查Block中是否包含V3签名
     */
    public static boolean hasV3Signature(byte[] sigBlock) {
        for (int id : getBlockIds(sigBlock)) {
            if (id == BLOCK_ID_V3 || id == BLOCK_ID_V31) return true;
        }
        return false;
    }

    // ========== 底层工具方法 ==========

    private static int findEocd(byte[] data) {
        // 从文件末尾向前搜索EOCD签名 0x06054b50
        for (int i = data.length - 22; i >= Math.max(0, data.length - 65557); i--) {
            if (data[i] == 0x50 && data[i + 1] == 0x4b
                    && data[i + 2] == 0x05 && data[i + 3] == 0x06) {
                return i;
            }
        }
        return -1;
    }

    private static int readInt32LE(byte[] data, int offset) {
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    private static long readInt64LE(byte[] data, int offset) {
        long lo = readInt32LE(data, offset) & 0xFFFFFFFFL;
        long hi = readInt32LE(data, offset + 4) & 0xFFFFFFFFL;
        return lo | (hi << 32);
    }

    private static void writeInt32LE(byte[] data, int offset, int value) {
        data[offset] = (byte) (value & 0xFF);
        data[offset + 1] = (byte) ((value >> 8) & 0xFF);
        data[offset + 2] = (byte) ((value >> 16) & 0xFF);
        data[offset + 3] = (byte) ((value >> 24) & 0xFF);
    }

    private static byte[] readFully(FileInputStream fis) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = fis.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        return bos.toByteArray();
    }
}
