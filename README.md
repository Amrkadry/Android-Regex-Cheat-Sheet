# Android Regex Cheat Sheet

A regex collection to help quickly perform static analysis on decompiled Android APKs. Designed for  detection of security controls (root / tamper / hooking), secrets, Raw SQL usage, Native library, WebView configurations, and more.

**Usage:** Decompile the APK, and search using these regex patterns to quickly locate relevant code.

![77](https://github.com/user-attachments/assets/a0225593-4ad1-40a6-a553-3ef8858a7e01)



## Security controls

**Regex:**

```regex
(?i)\b(root|rooted|isRoot|isDeviceRooted|checkRoot|check_root|RootBeer|magisk|su\b|superuser|mount\s*\(|/system/bin/su|/system/xbin/su|which\s+su|busybox|getprop|ro\.debuggable|ro\.secure|Build\.TAGS|android:debuggable|adb_enabled|frida|frida-gadget|xposed|XposedBridge|substrate|nativehook|hooking\hooked|SafetyNet|attestation|certificate pinning|pinning|CertificatePinner|isDebuggerConnected|Debug\.isDebuggerConnected|checkDebugger|isEmulator|emulator|qemu|ro\.product\.model|ro\.product\.device|ro\.build\.product|checkRootMethod|detectRoot)
```

## Secrets

**Regex:**

```regex
(?i)\bLog\.(?:d|e|w|i|v)\s*\(.*?\b(?:token|access_token|password|aws_secret_access_key|aws_access_key_id|pwd|pin|ssn|card|cvv|secret|access|api[_-]?key|client[_-]?secret|apikey|privatekey)\b.*?\)
```

## Exported / intent-filters / FileProvider misconfig

**Regex:**

```regex
(?i)\bandroid:exported\s*=\s*"(true)"|<provider\b|android:grantUriPermissions|fileprovider|FileProvider\b
```

## Native library / .so loader

**Regex:**

```regex
(?i)\b(System.loadLibrary|System\.load|NativeLibrary|lib.*\.so)\b
```

## Reflection / dynamic classloading / dex loading

**Regex:**

```regex
(?si)(?:\b(?:ClassLoader|DexClassLoader|PathClassLoader|InMemoryDexClassLoader|dalvik\.system\.DexFile|DexFile)\b|\b(?:Class\.forName|Class\.loadClass|getDeclaredMethod|getMethod|invoke|defineClass|loadClass|DexFile\.loadDex|loadDex|loadUrl|System\.loadLibrary|System\.load|Runtime(?:\.getRuntime\(\))?\.exec|Runtime\.exec|loadLibrary)\s*\()
```

## Network config file

**Regex:**

```regex
(?i)\bnetwork-security-config|pin-set|<pin\b|certificatePinner|CertificatePinner|pin\sdigest|pinning|CertificatePinner\b
```

## Keystore / password hints

**Regex:**

```regex
(?i)\b(keyStore|keystore|keyStorePassword|keyPassword|keystorePassword|storePassword|alias|keystoreFile)\b
```

## Signature / installer / tamper checks

**Regex:**

```regex
(?i)\b(?:getPackageManager|getPackageInfo|getSignatures|getSigningInfo|signingInfo|getApkContentsSigners|PackageManager\.GET_SIGNATURES|PackageManager\.GET_SIGNING_CERTIFICATES|checkSignature|verifySignature|compareSignatures)\b(?:\s*\()?
```

## Raw SQL usage

**Regex:**

```regex
(?i)\b(?:rawQuery|execSQL|String\.format\s*\(.*SELECT\b|SELECT\s+.*%s\b|\bWHERE\b.*%s)\b
```

## WebView

**Regex:**

```regex
(?i)\b(WebView|setJavaScriptEnabled|addJavascriptInterface|setAllowFileAccess|setAllowContentAccess|setAllowUniversalAccessFromFileURLs|setDomStorageEnabled|loadUrl|loadDataWithBaseURL)\b
```

## Debugger / Tracer checks

**Regex:**

```regex
(?i)\b(Debug\.isDebuggerConnected|isDebuggerConnected|android\.os\.Debug|ptrace|TracerPid|getCallingPid|getppid|tracerPid|Debuggable|android:debuggable)\b
```
