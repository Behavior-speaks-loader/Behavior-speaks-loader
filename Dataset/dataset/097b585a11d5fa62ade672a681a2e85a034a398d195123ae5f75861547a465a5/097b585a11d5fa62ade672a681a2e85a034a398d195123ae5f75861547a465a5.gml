graph [
  directed 1
  node [
    id 0
    label "Lcom/shell/NativeApplication;-><clinit>()V [access_flags=static constructor] @ 0xb1c"
    external False
    entrypoint False
  ]
  node [
    id 1
    label "Ljava/lang/System;->load(Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 2
    label "Lcom/shell/NativeApplication;-><init>()V [access_flags=public constructor] @ 0xb44"
    external False
    entrypoint False
  ]
  node [
    id 3
    label "Ljava/lang/Object;-><init>()V"
    external True
    entrypoint False
  ]
  node [
    id 4
    label "Lcom/shell/NativeApplication;->load(Landroid/app/Application; Ljava/lang/String;)Z [access_flags=public static native] @ 0x0"
    external False
    entrypoint False
  ]
  node [
    id 5
    label "Lcom/shell/NativeApplication;->run(Landroid/app/Application; Ljava/lang/String;)Z [access_flags=public static native] @ 0x0"
    external False
    entrypoint False
  ]
  node [
    id 6
    label "Lcom/shell/SuperApplication;-><init>()V [access_flags=public constructor] @ 0xb5c"
    external False
    entrypoint False
  ]
  node [
    id 7
    label "Landroid/app/Application;-><init>()V"
    external True
    entrypoint False
  ]
  node [
    id 8
    label "Lcom/shell/SuperApplication;->copyLib(Ljava/util/zip/ZipFile; Ljava/util/zip/ZipEntry; Ljava/io/File;)V [access_flags=private] @ 0xb74"
    external False
    entrypoint False
  ]
  node [
    id 9
    label "Ljava/io/FileOutputStream;->write([B I I)V"
    external True
    entrypoint False
  ]
  node [
    id 10
    label "Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V"
    external True
    entrypoint False
  ]
  node [
    id 11
    label "Ljava/io/File;->getParentFile()Ljava/io/File;"
    external True
    entrypoint False
  ]
  node [
    id 12
    label "Ljava/io/File;->mkdirs()Z"
    external True
    entrypoint False
  ]
  node [
    id 13
    label "Ljava/io/InputStream;->read([B)I"
    external True
    entrypoint False
  ]
  node [
    id 14
    label "Ljava/io/FileOutputStream;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 15
    label "Ljava/io/IOException;->printStackTrace()V"
    external True
    entrypoint False
  ]
  node [
    id 16
    label "Ljava/io/File;->exists()Z"
    external True
    entrypoint False
  ]
  node [
    id 17
    label "Ljava/io/InputStream;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 18
    label "Ljava/util/zip/ZipFile;->getInputStream(Ljava/util/zip/ZipEntry;)Ljava/io/InputStream;"
    external True
    entrypoint False
  ]
  node [
    id 19
    label "Lcom/shell/SuperApplication;->getCRC32(Ljava/io/File;)J [access_flags=public static] @ 0xbfc"
    external False
    entrypoint False
  ]
  node [
    id 20
    label "Ljava/util/zip/CheckedInputStream;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 21
    label "Ljava/io/FileInputStream;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 22
    label "Ljava/util/zip/CRC32;-><init>()V"
    external True
    entrypoint False
  ]
  node [
    id 23
    label "Ljava/util/zip/CheckedInputStream;->read([B)I"
    external True
    entrypoint False
  ]
  node [
    id 24
    label "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
    external True
    entrypoint False
  ]
  node [
    id 25
    label "Ljava/util/zip/CRC32;->getValue()J"
    external True
    entrypoint False
  ]
  node [
    id 26
    label "Ljava/util/zip/CheckedInputStream;-><init>(Ljava/io/InputStream; Ljava/util/zip/Checksum;)V"
    external True
    entrypoint False
  ]
  node [
    id 27
    label "Lcom/shell/SuperApplication;->attachBaseContext(Landroid/content/Context;)V [access_flags=protected] @ 0xd40"
    external False
    entrypoint False
  ]
  node [
    id 28
    label "Lcom/shell/SuperApplication;->loadLibs(Landroid/content/Context;)V [access_flags=protected] @ 0xe24"
    external False
    entrypoint False
  ]
  node [
    id 29
    label "Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V"
    external True
    entrypoint False
  ]
  node [
    id 30
    label "Ljava/io/BufferedReader;->readLine()Ljava/lang/String;"
    external True
    entrypoint False
  ]
  node [
    id 31
    label "Ljava/io/PrintStream;->println(Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 32
    label "Lcom/shell/SuperApplication;->copyLib(Ljava/lang/String;)V [access_flags=protected] @ 0xd68"
    external False
    entrypoint False
  ]
  node [
    id 33
    label "Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z"
    external True
    entrypoint False
  ]
  node [
    id 34
    label "Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;"
    external True
    entrypoint False
  ]
  node [
    id 35
    label "Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V"
    external True
    entrypoint False
  ]
  node [
    id 36
    label "Ljava/lang/Process;->getInputStream()Ljava/io/InputStream;"
    external True
    entrypoint False
  ]
  node [
    id 37
    label "Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V"
    external True
    entrypoint False
  ]
  node [
    id 38
    label "Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"
    external True
    entrypoint False
  ]
  node [
    id 39
    label "Ljava/lang/String;->equals(Ljava/lang/Object;)Z"
    external True
    entrypoint False
  ]
  node [
    id 40
    label "Ljava/util/zip/ZipEntry;->getCrc()J"
    external True
    entrypoint False
  ]
  node [
    id 41
    label "Lcom/shell/SuperApplication;->getPackageCodePath()Ljava/lang/String;"
    external True
    entrypoint False
  ]
  node [
    id 42
    label "Ljava/io/File;-><init>(Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 43
    label "Ljava/util/zip/ZipFile;-><init>(Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 44
    label "Ljava/util/zip/ZipFile;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 45
    label "Ljava/util/zip/ZipFile;->getEntry(Ljava/lang/String;)Ljava/util/zip/ZipEntry;"
    external True
    entrypoint False
  ]
  node [
    id 46
    label "Lcom/shell/SuperApplication;->onCreate()V [access_flags=public] @ 0xed0"
    external False
    entrypoint False
  ]
  node [
    id 47
    label "Landroid/app/Application;->onCreate()V"
    external True
    entrypoint False
  ]
  edge [
    source 0
    target 1
  ]
  edge [
    source 2
    target 3
  ]
  edge [
    source 6
    target 7
  ]
  edge [
    source 8
    target 9
  ]
  edge [
    source 8
    target 10
  ]
  edge [
    source 8
    target 11
  ]
  edge [
    source 8
    target 12
  ]
  edge [
    source 8
    target 13
  ]
  edge [
    source 8
    target 14
  ]
  edge [
    source 8
    target 15
  ]
  edge [
    source 8
    target 16
  ]
  edge [
    source 8
    target 17
  ]
  edge [
    source 8
    target 18
  ]
  edge [
    source 19
    target 20
  ]
  edge [
    source 19
    target 16
  ]
  edge [
    source 19
    target 21
  ]
  edge [
    source 19
    target 22
  ]
  edge [
    source 19
    target 23
  ]
  edge [
    source 19
    target 24
  ]
  edge [
    source 19
    target 25
  ]
  edge [
    source 19
    target 26
  ]
  edge [
    source 27
    target 4
  ]
  edge [
    source 27
    target 28
  ]
  edge [
    source 27
    target 29
  ]
  edge [
    source 28
    target 30
  ]
  edge [
    source 28
    target 31
  ]
  edge [
    source 28
    target 32
  ]
  edge [
    source 28
    target 33
  ]
  edge [
    source 28
    target 34
  ]
  edge [
    source 28
    target 35
  ]
  edge [
    source 28
    target 36
  ]
  edge [
    source 28
    target 37
  ]
  edge [
    source 28
    target 38
  ]
  edge [
    source 32
    target 39
  ]
  edge [
    source 32
    target 40
  ]
  edge [
    source 32
    target 41
  ]
  edge [
    source 32
    target 8
  ]
  edge [
    source 32
    target 42
  ]
  edge [
    source 32
    target 43
  ]
  edge [
    source 32
    target 44
  ]
  edge [
    source 32
    target 45
  ]
  edge [
    source 32
    target 19
  ]
  edge [
    source 46
    target 5
  ]
  edge [
    source 46
    target 47
  ]
]
