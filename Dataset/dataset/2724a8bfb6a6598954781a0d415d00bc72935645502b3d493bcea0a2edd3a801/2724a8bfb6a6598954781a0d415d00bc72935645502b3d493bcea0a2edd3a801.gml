graph [
  directed 1
  node [
    id 0
    label "Lcom/qihoo/util/StubApplication;-><init>()V [access_flags=public constructor] @ 0xc28"
    external False
    entrypoint False
  ]
  node [
    id 1
    label "Landroid/app/Application;-><init>()V"
    external True
    entrypoint False
  ]
  node [
    id 2
    label "Lcom/qihoo/util/StubApplication;->copy(Landroid/content/Context; Ljava/lang/String; Ljava/lang/String; Ljava/lang/String;)Z [access_flags=public static] @ 0xc40"
    external False
    entrypoint False
  ]
  node [
    id 3
    label "Ljava/lang/Exception;->printStackTrace()V"
    external True
    entrypoint False
  ]
  node [
    id 4
    label "Ljava/io/InputStream;->read([B)I"
    external True
    entrypoint False
  ]
  node [
    id 5
    label "Ljava/io/BufferedInputStream;-><init>(Ljava/io/InputStream;)V"
    external True
    entrypoint False
  ]
  node [
    id 6
    label "Ljava/io/File;->mkdir()Z"
    external True
    entrypoint False
  ]
  node [
    id 7
    label "Ljava/io/InputStream;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 8
    label "Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"
    external True
    entrypoint False
  ]
  node [
    id 9
    label "Ljava/lang/StringBuilder;-><init>()V"
    external True
    entrypoint False
  ]
  node [
    id 10
    label "Landroid/content/res/Resources;->getAssets()Landroid/content/res/AssetManager;"
    external True
    entrypoint False
  ]
  node [
    id 11
    label "Ljava/io/BufferedInputStream;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 12
    label "Landroid/content/Context;->getResources()Landroid/content/res/Resources;"
    external True
    entrypoint False
  ]
  node [
    id 13
    label "Ljava/io/FileOutputStream;->write([B I I)V"
    external True
    entrypoint False
  ]
  node [
    id 14
    label "Ljava/io/File;->exists()Z"
    external True
    entrypoint False
  ]
  node [
    id 15
    label "Ljava/io/FileOutputStream;-><init>(Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 16
    label "Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;"
    external True
    entrypoint False
  ]
  node [
    id 17
    label "Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V"
    external True
    entrypoint False
  ]
  node [
    id 18
    label "Ljava/io/File;-><init>(Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 19
    label "Lcom/qihoo/util/StubApplication;->isSameFile(Ljava/io/BufferedInputStream; Ljava/io/BufferedInputStream;)Z [access_flags=public static] @ 0xda0"
    external False
    entrypoint False
  ]
  node [
    id 20
    label "Ljava/io/File;->delete()Z"
    external True
    entrypoint False
  ]
  node [
    id 21
    label "Ljava/lang/StringBuilder;->toString()Ljava/lang/String;"
    external True
    entrypoint False
  ]
  node [
    id 22
    label "Ljava/io/FileOutputStream;->close()V"
    external True
    entrypoint False
  ]
  node [
    id 23
    label "Ljava/io/BufferedInputStream;->available()I"
    external True
    entrypoint False
  ]
  node [
    id 24
    label "Ljava/io/BufferedInputStream;->read([B)I"
    external True
    entrypoint False
  ]
  node [
    id 25
    label "Ljava/io/FileNotFoundException;->printStackTrace()V"
    external True
    entrypoint False
  ]
  node [
    id 26
    label "Ljava/io/IOException;->printStackTrace()V"
    external True
    entrypoint False
  ]
  node [
    id 27
    label "Lcom/qihoo/util/StubApplication;->isX86Arch()Ljava/lang/Boolean; [access_flags=public static] @ 0xe1c"
    external False
    entrypoint False
  ]
  node [
    id 28
    label "Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z"
    external True
    entrypoint False
  ]
  node [
    id 29
    label "Ljava/io/RandomAccessFile;-><init>(Ljava/lang/String; Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 30
    label "Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;"
    external True
    entrypoint False
  ]
  node [
    id 31
    label "Ljava/io/RandomAccessFile;->readLine()Ljava/lang/String;"
    external True
    entrypoint False
  ]
  node [
    id 32
    label "Lcom/qihoo/util/StubApplication;->attachBaseContext(Landroid/content/Context;)V [access_flags=protected] @ 0xf24"
    external False
    entrypoint False
  ]
  node [
    id 33
    label "Ljava/lang/Boolean;->booleanValue()Z"
    external True
    entrypoint False
  ]
  node [
    id 34
    label "Ljava/lang/System;->load(Ljava/lang/String;)V"
    external True
    entrypoint False
  ]
  node [
    id 35
    label "Landroid/content/Context;->getFilesDir()Ljava/io/File;"
    external True
    entrypoint False
  ]
  node [
    id 36
    label "Ljava/io/File;->getAbsolutePath()Ljava/lang/String;"
    external True
    entrypoint False
  ]
  node [
    id 37
    label "Landroid/app/Application;->attachBaseContext(Landroid/content/Context;)V"
    external True
    entrypoint False
  ]
  node [
    id 38
    label "Lcom/qihoo/util/StubApplication;->onCreate()V [access_flags=public] @ 0x1148"
    external False
    entrypoint False
  ]
  node [
    id 39
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
    source 2
    target 4
  ]
  edge [
    source 2
    target 5
  ]
  edge [
    source 2
    target 6
  ]
  edge [
    source 2
    target 7
  ]
  edge [
    source 2
    target 8
  ]
  edge [
    source 2
    target 9
  ]
  edge [
    source 2
    target 10
  ]
  edge [
    source 2
    target 11
  ]
  edge [
    source 2
    target 12
  ]
  edge [
    source 2
    target 13
  ]
  edge [
    source 2
    target 14
  ]
  edge [
    source 2
    target 15
  ]
  edge [
    source 2
    target 16
  ]
  edge [
    source 2
    target 17
  ]
  edge [
    source 2
    target 18
  ]
  edge [
    source 2
    target 19
  ]
  edge [
    source 2
    target 20
  ]
  edge [
    source 2
    target 21
  ]
  edge [
    source 2
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
    target 28
  ]
  edge [
    source 27
    target 29
  ]
  edge [
    source 27
    target 30
  ]
  edge [
    source 27
    target 31
  ]
  edge [
    source 27
    target 26
  ]
  edge [
    source 27
    target 25
  ]
  edge [
    source 32
    target 9
  ]
  edge [
    source 32
    target 33
  ]
  edge [
    source 32
    target 21
  ]
  edge [
    source 32
    target 28
  ]
  edge [
    source 32
    target 8
  ]
  edge [
    source 32
    target 34
  ]
  edge [
    source 32
    target 2
  ]
  edge [
    source 32
    target 27
  ]
  edge [
    source 32
    target 35
  ]
  edge [
    source 32
    target 30
  ]
  edge [
    source 32
    target 36
  ]
  edge [
    source 32
    target 37
  ]
  edge [
    source 38
    target 39
  ]
]
