# OpenCL import lib (Windows / MinGW)

`libOpenCL.a` is a MinGW import library generated from the system ICD
(`C:\Windows\System32\OpenCL.dll`) so `cargo build --features gpu` can link
without the Khronos SDK.

Regenerate on a Windows box with a GPU driver installed:

```
gendef C:\Windows\System32\OpenCL.dll
dlltool -d OpenCL.def -l libOpenCL.a -D OpenCL.dll
```

Runtime still loads the vendor ICD from the driver install; this archive is
link-only.
