# C扫指针工具

**Android ARM64 · 版本 1.2.2 · 作者：jx小新**

C扫指针工具是一款由 jx小新开发的原生 Android 指针链扫描工具，提供网页工作台、命令行和终端菜单。

## 功能

- 搜索进程内存中的指针链。
- 比较多次扫描结果，并按新的地址过滤链条。
- 查看进程、调试链条、导入和导出结果。
- 使用本机网页操作，无需 APK 或联网服务。

## 运行

在 Android 上将 `bin/cscan-android-arm64` 放到允许执行的位置，然后运行：

```sh
chmod +x cscan-android-arm64
./cscan-android-arm64
```

在同一设备的浏览器打开 `http://127.0.0.1:18760`。读取其他应用通常需要 Android 原生 Root 权限；工具不会自行提权或安装驱动。

扫描结果保存在本地的 `cscan-data/` 目录。启动脚本会将结果保存在 `data/`。这些目录已从 Git 提交中排除。

## 从源码构建

设置 `ANDROID_NDK_HOME` 指向已安装的 Android NDK 后运行：

```sh
bash scripts/build-android.sh
```

## 许可证

项目代码采用 MIT License。第三方组件保留各自的许可证与版权声明，见 `vendor/`。
