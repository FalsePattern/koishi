# koishi

This is [koishi](https://github.com/taisei-project/koishi), a portable C coroutine library, packaged for [Zig](https://ziglang.org/).

## How to use it

First, update your `build.zig.zon`:

```shell
zig fetch --save "git+https://github.com/FalsePattern/koishi/#master"
```

Next, add this snippet to your `build.zig` script:

```zig
const koishi_dep = b.dependency("koishi", .{
    .target = target,
    .optimize = optimize,
});
your_compilation.linkLibrary(koishi_dep.artifact("koishi"));
```

This will provide koishi as a static library to `your_compilation`.

## Additional options

```
.verbose = [bool]             Verbose logging for configure phase. [default: false]
.impl = [enum]                Which implementation to use. Leave empty to autodetect.
                                Supported Values:
                                  emscripten
                                  fcontext
                                  ucontext
                                  ucontext_e2k
                                  ucontext_sjlj
                                  win32fiber
.threadsafe = [bool]          Whether multiple coroutines can be ran on different threads at once (needs compiler support) [default: true]
.valgrind = [bool]            Enable support for running under Valgrind (for debugging) [default: false]
.linkage = [enum]             Whether the koishi library should be statically or dynamically linked. [default: static]
                                Supported Values:
                                  static
                                  dynamic
```

Using the emscripten implementation requires `-s ASYNCIFY` in your emscripten linker args!

## TODO

libboost is currently not supported. 