# AGENTS.md

本仓库 AI 编码代理工作指南。以下内容均已对照实际源码核实；若与本文件
冲突，以代码为准，并在事实变化时更新本文件。

## 项目概述

DirtyFrag (CVE-2026-43284) 是 [diabl0w/DFRoot](https://github.com/diabl0w/DFRoot)
的加固分支。它是一个 Android 应用(包名 `df.root`,应用名 "DirtyFrag"),
利用 Android 内核 IPsec ESP AES-CBC 处理流程中的内核页缓存写原语,
将 shellcode 补丁写入内核页缓存中的 `libc++.so`,在不解锁 Bootloader
的情况下加载内核模块(`dfroot.ko`),从而获得 root。本分支面向三星手机
(带 RKP/KDP/DEFEX 加固的 OneUI),并保持 SU 管理器无关:SU 守护进程
(`ksud`)在运行时从用户所选的任意 KernelSU 衍生管理器的 `libksud.so`
中暂存(stage)。

Root 是**临时的**:重启后一切消失,重启同时也是恢复手段。当前版本:
`versionName 1.11` / `versionCode 31`(`app/build.gradle.kts`)。

## 技术栈

- **应用**:Gradle (Kotlin DSL)、AGP 9.4.0,`compileSdk`/`targetSdk` 37,
  `minSdk` 32,Java 11 source/target,单模块 `:app`,仅 `arm64-v8a`。
- **UI**:经典 Android Views + ViewBinding(无 Compose);Material
  Components 1.13.0、androidx.appcompat 1.7.1、constraintlayout 2.2.1。
  版本固定于 `gradle/libs.versions.toml`。
- **原生层**:C + AArch64 汇编,经 NDK 通过 CMake 构建
  (`app/src/main/jni/CMakeLists.txt`)。原生组件以暂存二进制文件的
  形式 exec 执行,**不**通过 JNI 加载(自 1.10 起)。
- **内核模块**:`lkm/dfroot.c`,外部模块构建
  (`make -C $KDIR M=$PWD ARCH=arm64 LLVM=1`),按体积优化(`-Os`,
  去掉 unwind 表),因为 `.ko` 是通过漏洞逐页写入的。
- **LKM 工具链**:`ghcr.io/ylarod/ddk-min:<kmi>-<date>` 容器——本地用
  podman,CI 中用 GitHub Actions 容器。
- **工具**:`tools/trace_icon.py`(Python 3,仅标准库)从
  `tools/icon-source.png` 重新生成矢量启动图标。

## 仓库结构

- `app/` —— Android 应用(唯一的 Gradle 模块)。
  - `src/main/java/df/root/` —— Java 源码(见"代码组织")。
  - `src/main/jni/` —— 原生源码:`exp.c`(漏洞利用驱动)、`bootstrap.c`
    (获取 root 后的引导程序,以 root 运行)、`splicehelper.c`(无依赖
    静态辅助二进制,被拼接进 `crash_dump64`)、`elf_parser.c`、
    `libcxx.S` + `include.inc`(位置无关 shellcode 及 AArch64 常量)、
    `aes256.h`、`CMakeLists.txt`,以及 `ko/` 目录下八个预构建的
    `dfroot-<kmi>.ko` 文件。
  - `src/main/res/` —— 布局、drawable(矢量启动图标)、Inter 字体。
- `lkm/` —— 内核模块(`dfroot.c`、`Makefile`)。
- 仓库根目录的 `Makefile` —— 编排 keystore 生成、按 KMI 构建 LKM
  (经 podman)以及 APK 构建。见"已知坑":其中部分内容是从上游遗留、
  已与本分支的 Gradle 配置不符。
- `.github/workflows/build.yml` —— CI:矩阵式构建八个 LKM,然后构建
  APK,并在 `v*` 标签上创建 GitHub Release。
- `tools/` —— 图标源文件和图标描摹脚本。
- `README.md`、`CHANGELOG.md` —— 面向用户的文档;CI 从
  `CHANGELOG.md` 中提取发布说明。

## 构建命令

### APK

```sh
JAVA_HOME="<Android Studio jbr>" ./gradlew :app:assembleRelease
```

输出:`app/build/outputs/apk/release/dirtyfrag.apk`(文件名由
`app/build.gradle.kts` 中的 `androidComponents` 强制为 `dirtyfrag.apk`)。
Gradle 工具链固定为 Java 21(`gradle/gradle-daemon-jvm.properties`)。

**签名**:release(和 debug)构建均使用 `app/keystore.jks` 签名,该文件被
gitignore。Gradle 配置硬编码别名 `dirtyfrag`,store 密码和 key 密码均为
`dirtyfrag`,因此请完全按 README 所述生成开发 keystore:

```sh
keytool -genkeypair -v -keystore app/keystore.jks -alias dirtyfrag \
  -keyalg RSA -keysize 2048 -validity 10000 \
  -storepass dirtyfrag -keypass dirtyfrag
```

### 内核模块

`app/src/main/jni/ko/` 下的八个 `.ko` 文件在本分支中是**已提交**的
(强制添加——`.gitignore` 仍列出了该模式,但 git 跟踪优先),因此普通
clone 即可构建,无需 DDK 工具链。它们按 KMI 构建
(`android12-5.10` … `android17-6.18`):

- **CI 中**:`.github/workflows/build.yml` 的 `LKMs / <kmi>` 作业在
  `ylarod/ddk-min` 容器中构建并上传 `df-lkm-<kmi>` 构件。
- **本地**:`make app/src/main/jni/ko/dfroot-<kmi>.ko`(或直接用 `make`
  构建全部)会用同一镜像运行 podman;镜像标签从
  `.github/workflows/build.yml` 中解析。

**每当 `lkm/dfroot.c` 变更,必须重建全部八个 `.ko` 文件**(否则随附的
模块将与应用期望的不符),方式是运行 CI 工作流并将构件拷贝进
`app/src/main/jni/ko/`,或走本地 podman 流程。

### 测试

本项目中**没有测试套件**——无单元测试、无 instrumented 测试、无测试
目录。"验证"方式是:

- CI 必须构建全部八个 LKM 并组装 APK(push/标签上构建 release,PR 上构建
  debug)。
- 由维护者在真实三星硬件上验证发布版本;漏洞运行通过应用内日志(设备
  横幅 + `/dev/dfm*` 标记)和 `logcat`/`dmesg` 诊断。

不要自行发明测试框架;若要添加测试,遵循 Gradle/Android 惯例并将其接入
CI。

## CI 与发布流程

`.github/workflows/build.yml`:

1. `build-lkms` —— 八个 KMI 的矩阵构建,在特权 `ddk-min` 容器中构建并
   strip `dfroot.ko`,上传构件。
2. `build-dfroot` —— 将 LKM 构件下载到 `app/src/main/jni/ko/`,将 base64
   编码的 `KEYSTORE` 密钥解码为 `app/keystore.jks`(PR 上跳过,PR 改为
   构建 `assembleDebug` 而非 `assembleRelease`),构建 APK。
3. 在 `v*` 标签上:暂存 `DirtyFrag-<tag>.apk`,从 `CHANGELOG.md` 提取对应
   的 `## <ver>` 章节作为发布说明,用 `softprops/action-gh-release` 创建
   GitHub Release(需要 `permissions: contents: write`)。

发布版本升级 = `app/build.gradle.kts` 中的 `versionCode`/`versionName`
+ `CHANGELOG.md` 新增章节 + `v<version>` 标签。

## 代码组织

Java(`app/src/main/java/df/root/`,包 `df.root`):

- `MainActivity.java` —— 整个 UI:管理器选择器(枚举安装了带
  `libksud.so` 的应用)、Autorun / Auto reboot / KernelSU Modules /
  Expert mode 卡片、两阶段进度条、带"保存到 Downloads"的日志视图、
  更新提示 pill。
- `ExploitRunner.java` —— 将 `ksud`(来自所选管理器)和 `bootstrap`
  暂存到应用数据目录,构建 `IpSecTransform`(基于 loopback UDP 封装的
  AES-CBC/HMAC-SHA256),并以 `--encap-port/--sender-port/--spi/--aes-key`
  参数 exec 原生 `libdfroot.so`。
- `BootReceiver.java` —— 开机自启,受 Expert mode 门控,带失败运行
  互锁(失败后自我禁用)。若 `/dev/df` 存在则跳过。
- `IReporter.java` —— 单方法日志回调,由 activity 和 receiver 共同实现。
- `OneUiSwitch`、`TwoStepProgressView`、`BottomFadeView`、
  `VersionPillSpan` —— 自定义视图。

原生层(`app/src/main/jni/`):

- `exp.c` —— 漏洞利用驱动(构建为 `libdfroot.so`,因为 AGP 只把
  `lib*.so` 打包进 `nativeLibraryDir`,该目录可执行)。实现 CBC 页缓存写,
  将 `splicehelper` 补丁进 `crash_dump64`,把 `dfroot-<kmi>.ko` 写入一个
  带 `vendor_file` 标签的文件,挂钩 `std::ostream::sentry::sentry()`,
  然后监视 `/dev/df*` 标记文件并将其映射为进度行/退出码。`cleanup()`
  会把 crash_dump64 和 ko 目标文件的原始字节写回页缓存(先保存、后恢复;
  恢复顺序与补丁相反——vendor 文件仍需要 crash_dump 桥),否则系统的
  tombstone 机制会一直坏到重启。
- `bootstrap.c`(`libbootstrap.so`)—— 由模块 init 以 root 运行:直接
  读取 `/data/user_de/0/df.root/shared_prefs/dfroot.xml`,继承 zygote
  环境,将分区设为只读,可选地禁用模块,将 `ksud` 移动到
  `/data/adb/ksud` 并启动它。
- `splicehelper.c` —— 无依赖、静态、`-nostartfiles` 二进制;作为
  `crash_dump64` 被 exec,通过 `crash_dump` SELinux 域拼接/读取
  vendor 文件的 16 字节页。
- `libcxx.S`/`include.inc` —— 位置无关 shellcode 及 libc++ 挂钩载荷。
- `elf_parser.c`、`aes256.h` —— 符号查找和用于 IV 计算的 AES-ECB。

内核模块(`lkm/dfroot.c`):

- `dfroot_init` 通过 kprobe 解析 `kallsyms_lookup_name`,在存在 DEFEX 时经
  kprobe 绕过,将 SELinux 设为 permissive(写 `selinux_state`),并额外用
  post_handler 挂钩 `avc_has_perm_noaudit` 强制放行——有厂商守护进程会把
  enforcing 改回,且部分内核(某些 vivo 构建)`CONFIG_SECURITY_SELINUX_DEVELOP=n`
  根本没有运行时开关;另用 pre_handler 挂钩 `seccomp_run_filters`,把 app
  uid(≥10000)发起 `reboot(2)`(arm64 syscall 142)时厂商 seccomp 策略的
  KILL 判定降级为 ALLOW——vivo/OriginOS 的杀进程策略会秒杀 KernelSU
  ≥2.0 的 reboot "supercall" 探测,导致管理器每次启动/软重启后卡死约
  60 秒("Shell check timeout";上游 issue tiann/KernelSU#3061/#2942)。
  crash_dump64 的页缓存清理**不再**由模块做(它与 exp.c 的恢复存在竞态:
  一旦把 splicehelper 页丢掉,cleanup 就没法再用 crash_dump 桥恢复 vendor
  文件),改由 exp.c `cleanup()` 写字节恢复。在存在 OPPO 安全模块时
  `rmmod` 它们,并用 `call_usermodehelper` exec 引导 shell。kprobe 保存在
  静态全局变量中,并有真正的 `module_exit`,以便 bootstrap 在 late-load
  后 `rmmod dfroot`(这正是软重启能配合所有 KernelSU 衍生品工作的原因)。

需要遵守的跨组件约定:

- **标记协议**:各组件通过 `touch` `/dev/df`、`/dev/dfm0`…`/dev/dfm6`、
  `/dev/dfmw0/1`、`/dev/dfme0`…`2` 来上报进度;映射表在 `exp.c` 中。
  任何新的 bootstrap/模块步骤都需要在那里添加标记条目。
- **偏好设置**:`SharedPreferences "dfroot"`,位于**设备保护存储**
  (`/data/user_de/0/df.root/shared_prefs/dfroot.xml`),键包括
  `su_manager`、`soft_reboot`、`auto_soft_reboot`、`disable_modules`、
  `expert_mode`。`bootstrap.c` 手工解析该 XML——键必须保持简单的
  `<boolean|string ...>` 条目形式。
- **一次性互斥锁**:`/dev/df` 防止 libc++ 挂钩被重复进入;失败的运行也会
  在 UI 中锁定 Run 按钮直到重启(页缓存补丁所致)。

## 代码风格

- Java:4 空格缩进,不用 tab,花括号同行;注释解释*为什么*(字段级约定),
  而非是什么。日志用 `TAG = "dfroot"`。
- C:4 空格缩进,K&R 风格,`-Wall -Wextra` 无警告,注释解释行为/风险
  (例如 `lkm/dfroot.c` 中的页缓存失效注意事项)。内核代码遵循上游内核
  模块惯例,并在 CFI 重要处加 `__nocfi` 注解。
- 资源:启动图标是矢量图(adaptive foreground/background/monochrome);
  通过 `tools/trace_icon.py` 重新生成,不要手改路径数据。
- 所有文档和注释的语言为**英文**。

## 安全注意事项

- 本仓库是一个**可用的 root 漏洞利用工具**(CVE-2026-43284)。对
  `exp.c`、`lkm/dfroot.c`、`bootstrap.c` 和 `splicehelper.c` 的修改
  都属于安全敏感面:这些代码故意绕过所有者自己设备上的
  SELinux/DEFEX/RKP 缓解机制。在不了解漏洞利用链的情况下,不要对这些
  路径做"加固"或重构(README 的 "How it works" 是必读内容)。
- 该漏洞仅针对运行它的设备;除 manifest 中已有的权限(`INTERNET`、
  `RECEIVE_BOOT_COMPLETED`、`WAKE_LOCK`、`QUERY_ALL_PACKAGES`)外不需要
  其他权限。保持现状——未经维护者决定不新增权限。
- 安全互锁是特性而非繁文缛节:Autorun 的失败自我禁用、Expert-mode
  门控、`/dev/df` 一次性互斥锁,以及无需 root 即可工作的 "KernelSU
  Modules" 开关。请保留它们。
- 永远不要提交 `app/keystore.jks` 或签名材料;CI 使用 base64 密钥。
- manifest 中故意设置了 `android:debuggable="true"`(漏洞利用工具的
  需要);上游也是如此发布的。

## 已知坑

- 仓库根目录的 `Makefile` 部分是从上游遗留的:它的 `keystore.jks` /
  `signing.properties` 目标(仓库根目录、密码 `df-ksu`)与本分支**不**
  符——本分支的 Gradle 配置硬编码 `app/keystore.jks`、密码 `dirtyfrag`,
  且从不读取 `signing.properties`。它最后的 `cp` 也期望 `DFRoot_*.apk`,
  而构建现在产出的是 `dirtyfrag.apk`。其中的 LKM podman 循环仍然准确。
  APK 构建请优先使用 README 中的 Gradle/keytool 命令;只有当你打算
  修复它时才重新生成该 Makefile。
- `app/proguard-rules.pro` 的注释中提到了 JNI 绑定——自 1.10 起已过时,
  漏洞利用现在是暂存可执行文件。keep 规则本身无害。
- `.gitignore` 中的 `app/src/main/jni/ko/*.ko` 模式不会取消已提交的
  `.ko` 文件的跟踪;不要误用 `git rm` 删除它们。
- 只修改 `lkm/dfroot.c` 而不重建八个 `.ko` 文件(CI 或 podman)会发布
  与应用不匹配的模块——见"内核模块"一节。
- vivo/iQOO(OriginOS)对 app 进程有额外的 seccomp 杀进程策略(针对
  `reboot` 系统调用),KernelSU ≥2.0 管理器的每次 feature check / su 探测
  都会被秒杀,表现为管理器退回后台再进入时卡死约 60 秒、装模块软重启后
  同样卡死。`dfroot.ko` 的 `seccomp_run_filters` kprobe 就是为此存在;
  若该符号不在 kallsyms(需 `CONFIG_KALLSYMS_ALL`),dmesg 会打印
  "seccomp_run_filters not in this kernel, skipping",此时 vivo 设备
  仍会出现上述卡死。
