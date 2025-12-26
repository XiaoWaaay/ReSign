package com.xwaaa.resig;

import android.content.Context;
import android.content.pm.Signature;
import android.os.Environment;
import android.util.Base64;
import android.util.Log;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;

public class Core {
    static String TAG = "去签 Core代码";
    Appinfos appinfo;
    Context context;

    public Core(Appinfos appinfo, Context context) {
        this.appinfo = appinfo;
        this.context = context;
    }
    public void begin(){
        File[] dex_s=null;
        String targetPackagePath = this.appinfo.getPackagePath();
        String targetPackageName = this.appinfo.getPackageName();
        Log.d(TAG,"去签APP路径："+targetPackagePath+"\n去签APP的包名："+targetPackageName);

        //拼接一下目录路径
        String workDir=this.context.getFilesDir().getAbsolutePath()+'/'+targetPackageName;
        Log.d(TAG,"工作路径："+workDir);

        try{
            //读取目标路径与工作目录，然后将其复制拷贝到工作目录
            FileUtils.INSTANCE.copyFile(targetPackagePath,workDir);
            Log.d(TAG,"将原文件复制到工作目录成功");
            appinfo.ensureSignatures(context);
            Log.d(TAG,"调用appinfo去获取原始签名值");
//            Signature signature2 = this.appinfo.getSignatures()[0];  // ✅ 直接拿签名，不再重新计算
//            byte[] byteArray2 = signature2.toByteArray();
//            String Sig2 = Base64.encodeToString(byteArray2, 0); // 获取签名值
//            Log.d("签名1",Sig2);
            //拼接获取一下这个复制到的新文件
            String apkPath=workDir+"/base.apk";
            //接下来就是进行解压操作了，就是将apk文件和xml文件进行解压
            try{
                FileUtils.INSTANCE.extractDexFile(apkPath,workDir);
                Log.d(TAG,"解压dex文件成功");

                //接下来尝试解压xml文件，还是先拼接路径然后再进行解压，这里单独解压xml是为了获取一些类名
                String xmlPath=workDir+"/AndroidManifest.xml";
                try {
                    FileUtils.INSTANCE.extractXmlFile(apkPath,workDir);
                    //下面就是遍历dex了,接收所有的dex文件
                    File file=new File(workDir);
                    File[] files=file.listFiles(new FilenameFilter() {
                        @Override
                        public boolean accept(File dir,String name) {
                            return name.contains(".dex");
                        }
                    });
                    //接下来也是关键的一个步骤，就是注入咱们的dex文件
                    Log.d(TAG,"xml路径："+xmlPath);
                    Injector.Companion.injectDex(workDir,xmlPath);
                    FileUtils.INSTANCE.copyAssetToFile(this.context, "classesx.dex", workDir, "classesx.dex");
                    //现在就是替换我们添加的那个dex中的签名值了，因为要考虑长度问题，我们进行base64编码
                    Signature signature = this.appinfo.getSignatures()[0];  //直接拿签名，不再重新计算
                    byte[] byteArray = signature.toByteArray();
                    String Sig = Base64.encodeToString(byteArray, 0); // 获取签名值
                    Log.d("签名",Sig);
                    Injector.Companion.editShellDEX(workDir + "/classesx.dex", this.appinfo.getPackageName(), Sig);
                    Log.d(TAG,"修改注入的dex中的签名值和包名");
                    int length = files.length;
                    Injector.Companion.renameFile(new File(workDir + "/classesx.dex"), new File(workDir + "/classes" + (length + 1) + ".dex"));
                    try{
                        FileUtils.INSTANCE.copyFile(workDir + File.separator+ "base.apk", workDir + File.separator, "origin.apk");
                        Log.d(TAG, "injectDexCode: 拷贝base.apk to origin.apk");
                        FileUtils.INSTANCE.copyAssetToFile(this.context, "libkillsignture.so", workDir, "libkillsignture.so");
                        File[] dex_s2 = new File(workDir).listFiles(new FilenameFilter() {
                            @Override // java.io.FilenameFilter
                            public boolean accept(File dir, String name) {
                                return name.contains(".dex");
                            }
                        });
                        int length2 = dex_s2.length;
                        int i = 0;
                        while (i < length2) {
                            String apkPath2 = apkPath;
                            File dex = dex_s2[i];
                            int i2 = length2;
                            try {
                                FileUtils.INSTANCE.addToZip(dex, workDir + "/base.apk", "");
                                dex_s = dex_s2;
                            } catch (Exception e) {
                                e = e;
                            }
                            try {
                                Log.d(TAG, "begin: add dex " + dex.getName());
                                i++;
                                apkPath = apkPath2;
                                length2 = i2;
                                dex_s2 = dex_s;

                            } catch (Exception e5) {
                                Log.e("Error","添加压缩文件报错"+e5);
                                throw new RuntimeException(e5);
                            }
                        }

                        try{

                            FileUtils.INSTANCE.addToZip(new File(workDir + "/origin.apk"), workDir + "/base.apk", "assets/KillSig/");
                            Log.d(TAG, "begin: add origin");
                            FileUtils.INSTANCE.addToZip(new File(workDir + "/libkillsignture.so"), workDir + "/base.apk", "lib/arm64-v8a/");
                            Log.d(TAG, "begin: add libkillsignture.so");
                            FileUtils.INSTANCE.addToZip(new File(workDir + "/AndroidManifest.xml"), workDir + "/base.apk", "");
                            Log.d(TAG, "begin: add AndroidManifest");
                            Log.d(TAG, "完成");
                            File[] files1 = new File(workDir).listFiles(new FilenameFilter() { // from class: com.crack.sigkill.business.Core.3
                                @Override // java.io.FilenameFilter
                                public boolean accept(File dir, String name) {
                                    return !name.equals("base.apk");
                                }
                            });
                            int i3 = 0;
                            for (int length3 = files1.length; i3 < length3; length3 = length3) {
                                File file_2 = files1[i3];
                                file_2.delete();
                                Log.d(TAG, "删除文件：" + file_2.getName());
                                i3++;
                            }
                            String downloadPath = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath();

                            try {
                                FileUtils.INSTANCE.copyFile(workDir + "/base.apk", downloadPath, targetPackageName+"_去签.apk");
                                Log.d(TAG, "begin: 输出成功！  路径：" + downloadPath);
                            } catch (IOException e7) {
                                throw new RuntimeException(e7);
                            }

                        }catch (Exception e6){
                            Log.e("Error","压缩文件报错2"+e6);
                        }

                    }catch (Exception e4){
                        Log.e("Error","so注入报错"+e4);
                    }
                }catch (Exception e3){
                    Log.e("Error","从APK中解压xml文件报错"+e3);
                }
            }catch (Exception e2){
                Log.e("Error","解压dex文件出错");
            }

        }catch (Exception e1){
            Log.e("Error","将原文件复制到工作目录出错，请检查是否有参数错误");
        }

    }


}
