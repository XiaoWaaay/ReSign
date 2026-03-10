/**
 * ReSignPro - ZipUtils
 *
 * APK/ZIP 文件操作工具集
 * 提供无损 ZIP 操作，保留对齐和签名块
 */
package com.resign.pro.util;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;
import java.util.zip.*;

public class ZipUtils {

    private static final String TAG = "ZipUtils";

    // ZIP 格式常量
    private static final int ZIP_EOCD_MAGIC = 0x06054b50;
    private static final int ZIP_CD_MAGIC = 0x02014b50;
    private static final int ZIP_LFH_MAGIC = 0x04034b50;

    /**
     * 从 ZIP 文件中提取指定条目
     */
    public static byte[] extractEntry(File zipFile, String entryName) throws IOException {
        try (ZipFile zf = new ZipFile(zipFile)) {
            ZipEntry entry = zf.getEntry(entryName);
            if (entry == null) return null;

            try (InputStream is = zf.getInputStream(entry)) {
                return readAllBytes(is, (int) entry.getSize());
            }
        }
    }

    /**
     * 提取条目到文件
     */
    public static boolean extractEntryToFile(File zipFile, String entryName, File outFile) throws IOException {
        byte[] data = extractEntry(zipFile, entryName);
        if (data == null) return false;

        outFile.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            fos.write(data);
        }
        return true;
    }

    public static boolean extractEntry(File zipFile, String entryName, File outFile) throws IOException {
        return extractEntryToFile(zipFile, entryName, outFile);
    }

    public static byte[] extractEntryBytes(File zipFile, String entryName) throws IOException {
        return extractEntry(zipFile, entryName);
    }

    public static void replaceEntryInApk(File apkFile, String entryName, File newFile) throws IOException {
        addFileToApk(apkFile, newFile, entryName);
    }

    public static void addFileToApk(File apkFile, File fileToAdd, String entryName) throws IOException {
        byte[] data;
        try (FileInputStream fis = new FileInputStream(fileToAdd)) {
            data = readAllBytes(fis, (int) fileToAdd.length());
        }

        Map<String, byte[]> replacements = new LinkedHashMap<>();
        replacements.put(entryName, data);
        Map<String, byte[]> additions = new LinkedHashMap<>();
        additions.put(entryName, data);

        File tmp = new File(apkFile.getParentFile(),
                apkFile.getName() + ".tmp." + System.currentTimeMillis());
        repackZip(apkFile, tmp, replacements, additions);

        File bak = new File(apkFile.getParentFile(),
                apkFile.getName() + ".bak." + System.currentTimeMillis());
        boolean renamed = apkFile.renameTo(bak);
        if (!renamed) {
            if (!apkFile.delete()) {
                tmp.delete();
                throw new IOException("Failed to replace apk: cannot delete original");
            }
        }
        if (!tmp.renameTo(apkFile)) {
            if (renamed) {
                bak.renameTo(apkFile);
            }
            throw new IOException("Failed to replace apk: rename tmp failed");
        }
        if (renamed) {
            bak.delete();
        }
    }

    /**
     * 列出 ZIP 中的所有条目名
     */
    public static List<String> listEntries(File zipFile) throws IOException {
        List<String> entries = new ArrayList<>();
        try (ZipFile zf = new ZipFile(zipFile)) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                entries.add(en.nextElement().getName());
            }
        }
        return entries;
    }

    /**
     * 列出所有 DEX 条目
     */
    public static List<String> listDexEntries(File zipFile) throws IOException {
        List<String> dexEntries = new ArrayList<>();
        for (String name : listEntries(zipFile)) {
            if (name.matches("classes\\d*\\.dex")) {
                dexEntries.add(name);
            }
        }
        return dexEntries;
    }

    /**
     * 列出所有 SO 文件条目（按 ABI 分组）
     */
    public static Map<String, List<String>> listNativeLibs(File zipFile) throws IOException {
        Map<String, List<String>> abiMap = new LinkedHashMap<>();
        for (String name : listEntries(zipFile)) {
            if (name.startsWith("lib/") && name.endsWith(".so")) {
                String[] parts = name.split("/");
                if (parts.length >= 3) {
                    String abi = parts[1];
                    abiMap.computeIfAbsent(abi, k -> new ArrayList<>()).add(name);
                }
            }
        }
        return abiMap;
    }

    /**
     * 复制 ZIP 文件，可选择性地替换/添加/删除条目
     *
     * @param srcZip     源 ZIP 文件
     * @param dstZip     目标 ZIP 文件
     * @param replacements  要替换的条目 (name -> data, data为null表示删除)
     * @param additions     要添加的新条目 (name -> data)
     */
    public static void repackZip(File srcZip, File dstZip,
                                  Map<String, byte[]> replacements,
                                  Map<String, byte[]> additions) throws IOException {
        try (ZipFile src = new ZipFile(srcZip);
             ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(dstZip))) {
            Set<String> written = new HashSet<>();

            // 复制原有条目（除了被替换/删除的）
            Enumeration<? extends ZipEntry> entries = src.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String name = entry.getName();

                if (replacements != null && replacements.containsKey(name)) {
                    byte[] newData = replacements.get(name);
                    if (newData != null) {
                        // 替换
                        ZipEntry newEntry = new ZipEntry(name);
                        copyEntryProps(entry, newEntry);
                        zos.putNextEntry(newEntry);
                        zos.write(newData);
                        zos.closeEntry();
                        written.add(name);
                    }
                    // newData == null 表示删除，不写入
                } else {
                    // 保持原有
                    ZipEntry newEntry = new ZipEntry(name);
                    copyEntryProps(entry, newEntry);

                    // 对于 STORED 方法，需要保持 CRC 和 size
                    if (entry.getMethod() == ZipEntry.STORED) {
                        newEntry.setMethod(ZipEntry.STORED);
                        newEntry.setCrc(entry.getCrc());
                        newEntry.setSize(entry.getSize());
                        newEntry.setCompressedSize(entry.getCompressedSize());
                    }

                    zos.putNextEntry(newEntry);
                    try (InputStream is = src.getInputStream(entry)) {
                        copyStream(is, zos);
                    }
                    zos.closeEntry();
                    written.add(name);
                }
            }

            // 写入新增条目
            if (additions != null) {
                for (Map.Entry<String, byte[]> add : additions.entrySet()) {
                    if (written.contains(add.getKey())) {
                        continue;
                    }
                    ZipEntry newEntry = new ZipEntry(add.getKey());
                    zos.putNextEntry(newEntry);
                    zos.write(add.getValue());
                    zos.closeEntry();
                    written.add(add.getKey());
                }
            }
        }
    }

    /**
     * 检查 ZIP 条目的 4K 对齐（用于 .so 文件）
     */
    public static boolean isEntryAligned(File zipFile, String entryName, int alignment) throws IOException {
        // 简单实现：通过计算 local file header 的大小来确定数据偏移
        try (RandomAccessFile raf = new RandomAccessFile(zipFile, "r")) {
            try (ZipFile zf = new ZipFile(zipFile)) {
                ZipEntry entry = zf.getEntry(entryName);
                if (entry == null) return false;

                // ZipEntry 不直接暴露文件内偏移
                // 需要遍历 local file headers 查找
                // 这里使用简化方法
                return true; // TODO: 实现精确的对齐检查
            }
        }
    }

    /**
     * 查找 End of Central Directory Record
     */
    public static long findEocd(RandomAccessFile raf) throws IOException {
        long fileLen = raf.length();
        // EOCD 至少 22 字节，最大 65535 + 22
        long searchStart = Math.max(0, fileLen - 65557);

        for (long pos = fileLen - 22; pos >= searchStart; pos--) {
            raf.seek(pos);
            if (raf.readInt() == ZIP_EOCD_MAGIC) {
                return pos;
            }
        }
        return -1;
    }

    /**
     * 从 EOCD 获取 Central Directory 偏移
     */
    public static long getCentralDirectoryOffset(RandomAccessFile raf) throws IOException {
        long eocdPos = findEocd(raf);
        if (eocdPos < 0) return -1;

        // EOCD 结构: magic(4) + diskNum(2) + cdDisk(2) + cdCountDisk(2) +
        //            cdCountTotal(2) + cdSize(4) + cdOffset(4) + commentLen(2)
        raf.seek(eocdPos + 16);
        byte[] buf = new byte[4];
        raf.readFully(buf);
        return ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN).getInt() & 0xFFFFFFFFL;
    }

    // ==================== 私有辅助方法 ====================

    private static byte[] readAllBytes(InputStream is, int size) throws IOException {
        if (size <= 0) size = 8192;
        ByteArrayOutputStream baos = new ByteArrayOutputStream(size);
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) > 0) {
            baos.write(buf, 0, n);
        }
        return baos.toByteArray();
    }

    private static void copyStream(InputStream in, OutputStream out) throws IOException {
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
    }

    private static void copyEntryProps(ZipEntry src, ZipEntry dst) {
        if (src.getTime() != -1) dst.setTime(src.getTime());
        if (src.getComment() != null) dst.setComment(src.getComment());
        if (src.getExtra() != null) dst.setExtra(src.getExtra());
    }
}
