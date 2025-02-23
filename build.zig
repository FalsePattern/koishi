const std = @import("std");
const builtin = @import("builtin");
const Zeson = @import("Zeson.zig");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const verbose = b.option(bool, "verbose", "Verbose logging for configure phase. [default: false]") orelse false;
    var impl: ?Backend = b.option(Backend, "impl", "Which implementation to use. Leave empty to autodetect.");
    const thread_safe = b.option(bool, "threadsafe", "Whether multiple coroutines can be ran on different threads at once (needs compiler support) [default: true]") orelse true;
    const valgrind = b.option(bool, "valgrind", "Enable support for running under Valgrind (for debugging) [default: false]") orelse false;
    const linkage: std.builtin.LinkMode = b.option(std.builtin.LinkMode, "linkage", "Whether the koishi library should be statically or dynamically linked. [default: static]") orelse .static;
    const upstream = b.dependency("koishi", .{});
    const cc = Zeson {
        .b = b,
        .target = target,
        .verbose = verbose,
        .tmp_dir = b.makeTempPath(),
    };
    var koishi_args = std.ArrayList([]const u8).init(b.allocator);
    defer koishi_args.deinit();
    var koishi_incdirs = std.ArrayList(std.Build.LazyPath).init(b.allocator);
    defer koishi_incdirs.deinit();
    try koishi_incdirs.append(upstream.path("include"));
    if (thread_safe) {
        if (cc.links("int _Thread_local i; int main() {};", "_Thread_local keyword support test", &.{})) {
            try koishi_args.append("-DKOISHI_THREAD_LOCAL=_Thread_local");
        } else if (cc.links("int __thread i; int main() {};", "__thread keyword support test", &.{})) {
            try koishi_args.append("-DKOISHI_THREAD_LOCAL=__thread");
        } else {
            try koishi_args.append("-DKOISHI_THREAD_LOCAL=");
            if (verbose) {
                std.Progress.lockStdErr();
                defer std.Progress.unlockStdErr();
                std.debug.print("Thread-local storage is not supported by compiler, the library will not be thread-safe", .{});
            }
        }
    } else {
        try koishi_args.append("-DKOISHI_THREAD_LOCAL=");
    }
    if (cc.hasFunction("mmap", .{.args = feature_args})) {
        if (cc.hasHeaderSymbol("sys/mman.h", "MAP_ANONYMOUS", .{.args = feature_args})) {
            try koishi_args.appendSlice(&.{"-DKOISHI_HAVE_MMAP", "-DKOISHI_MAP_ANONYMOUS=MAP_ANONYMOUS"});
        } else if (cc.hasHeaderSymbol("sys/mman.h", "MAP_ANON", .{.args = feature_args})) {
            try koishi_args.appendSlice(&.{"-DKOISHI_HAVE_MMAP", "-DKOISHI_MAP_ANONYMOUS=MAP_ANON"});
        }

        if (cc.hasHeaderSymbol("sys/mman.h", "MAP_STACK", .{.args = feature_args})) {
            try koishi_args.append("-DKOISHI_MAP_STACK=MAP_STACK");
        } else {
            try koishi_args.append("-DKOISHI_MAP_STACK=0");
        }
    }
    var can_get_page_size = false;
    if (cc.hasFunction("sysconf", .{.args = feature_args})) {
        if (cc.hasHeaderSymbol("unistd.h", "_SC_PAGE_SIZE", .{.args = feature_args})) {
            try koishi_args.appendSlice(&.{"-DKOISHI_HAVE_SYSCONF", "-DKOISHI_SC_PAGE_SIZE=_SC_PAGE_SIZE"});
            can_get_page_size = true;
        } else if (cc.hasHeaderSymbol("unistd.h", "_SC_PAGESIZE", .{.args = feature_args})) {
            try koishi_args.appendSlice(&.{"-DKOISHI_HAVE_SYSCONF", "-DKOISHI_SC_PAGE_SIZE=_SC_PAGESIZE"});
            can_get_page_size = true;
        }
    }
    if (cc.hasFunction("getpagesize", .{.args = feature_args})) {
        try koishi_args.append("-DKOISHI_HAVE_GETPAGESIZE");
        can_get_page_size = true;
    }
    if (cc.hasFunction("aligned_alloc", .{.args = feature_args})) {
        try koishi_args.append("-DKOISHI_HAVE_ALIGNED_ALLOC");
    }
    if (cc.hasFunction("posix_memalign", .{.args = feature_args})) {
        try koishi_args.append("-DKOISHI_HAVE_POSIX_MEMALIGN");
    }
    if (target.result.os.tag == .windows) {
        try koishi_args.append("-DKOISHI_HAVE_WIN32API");
        can_get_page_size = true;
    }

    if (!can_get_page_size) {
        const static_page_size = 4096;
        try koishi_args.append(std.fmt.comptimePrint("-DKOISHI_STATIC_PAGE_SIZE={}", .{static_page_size}));
        if (verbose) {
            std.Progress.lockStdErr();
            defer std.Progress.unlockStdErr();
            std.debug.print("No way to detect page size at runtime, assuming {}\n", .{static_page_size});
        }
    }
    const koishi = Koishi{
        .sjlj = try sjljKoishi(cc),
        .upstream = upstream,
    };
    if (koishi.sjlj.len > 0) {
        try koishi_args.append(b.fmt("-DKOISHI_SJLJ_{s}", .{koishi.sjlj}));
    }
    if (valgrind) {
        try koishi_args.append("-DKOISHI_VALGRIND");
    }
    if (verbose) {
        std.Progress.lockStdErr();
        defer std.Progress.unlockStdErr();
        std.debug.print("Configuration args:", .{});
        for (koishi_args.items) |item| {
            std.debug.print(" {s}", .{item});
        }
        std.debug.print("\n", .{});
    }
    try koishi_args.append("-DBUILDING_KOISHI");
    try koishi_args.appendSlice(feature_args);
    try koishi_args.appendSlice(warn_args);
    var koishi_src = std.ArrayList([]const u8).init(b.allocator);
    defer koishi_src.deinit();

    try koishi_src.append(b.pathJoin(&.{"src", "stack_alloc.c"}));

    {
        const is_auto_pick = impl == null;
        impl, const params = try pickBackend(cc, koishi, impl);
        defer {
            if (params.args) |args| b.allocator.free(args);
            b.allocator.free(params.src);
        }
        try koishi_src.appendSlice(params.src);
        if (params.args) |args| {
            try koishi_args.appendSlice(args);
        }

        if (verbose) {
            std.Progress.lockStdErr();
            defer std.Progress.unlockStdErr();
            if (is_auto_pick) {
                std.debug.print("Using the {s} backend (auto)\n", .{@tagName(impl.?)});
            } else {
                std.debug.print("Using the {s} backend (manual)\n", .{@tagName(impl.?)});
            }
        }
    }

    const koishi_lib = b.addLibrary(.{
        .linkage = linkage,
        .name = "koishi",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });
    koishi_lib.addCSourceFiles(.{
        .root = upstream.path(""),
        .files = try koishi_src.toOwnedSlice(),
        .flags = try koishi_args.toOwnedSlice(),
    });
    for (koishi_incdirs.items) |inc| {
        koishi_lib.addIncludePath(inc);
    }
    koishi_lib.installHeadersDirectory(upstream.path("include"), "", .{});
    koishi_lib.linkLibC();
    b.installArtifact(koishi_lib);
    const test_exe = b.addExecutable(.{
        .name = "koishi_test",
        .target = target,
        .optimize = optimize,
        .linkage = linkage,
        .single_threaded = !thread_safe,
    });
    test_exe.addCSourceFile(.{ .file = upstream.path("koishi_test.c") });
    test_exe.linkLibrary(koishi_lib);
    const run_test = b.addRunArtifact(test_exe);
    const test_step = b.step("test", "Run koishi_test");
    test_step.dependOn(&run_test.step);
    const benchmark_exe = b.addExecutable(.{
        .name = "koishi_benchmark",
        .target = target,
        .optimize = optimize,
        .single_threaded = !thread_safe,
    });
    benchmark_exe.addCSourceFile(.{ .file = upstream.path("koishi_benchmark.c") });
    benchmark_exe.linkLibrary(koishi_lib);
    const run_benchmark = b.addRunArtifact(benchmark_exe);
    const benchmark_step = b.step("benchmark", "Run koishi_benchmark");
    benchmark_step.dependOn(&run_benchmark.step);
}
const feature_args: []const []const u8 = &.{
    "-D_BSD_SOURCE",
    "-D_DARWIN_C_SOURCE",
    "-D_DEFAULT_SOURCE",
    "-D_GNU_SOURCE",
    "-D_POSIX_C_SOURCE=200809L",
    "-D_XOPEN_SOURCE=700",
};
const warn_args: []const []const u8 = &.{
    "-Wall",
    "-Wpedantic",
    "-Werror=implicit-function-declaration",
    "-Werror=incompatible-pointer-types",
    "-Wmissing-prototypes",
    "-Wstrict-prototypes",
};

const Koishi = struct {
    sjlj: []const u8,
    upstream: *std.Build.Dependency,
};

fn sjljKoishi(meson: Zeson) ![]const u8 {
    const b = meson.b;
    return inline for (.{
        .{"SIG", "#include <setjmp.h>\nint main() { sigjmp_buf buf; if(sigsetjmp(buf, 0)) siglongjmp(buf, 1); }", "sigsetjmp/siglongjmp"},
        .{"BSD", "#include <setjmp.h>\nint main() { jmp_buf buf; if(_setjmp(buf)) _longjmp(buf, 1); }", "_setjmp/_longjmp"},
        .{"STD", "#include <setjmp.h>\nint main() { jmp_buf buf; if(setjmp(buf)) longjmp(buf, 1); }", "setjmp/longjmp"},
    }) |tuple| {
        const name = try std.fmt.allocPrint(b.allocator, "{s} test", .{tuple[2]});
        defer b.allocator.free(name);
        if (meson.links(tuple[1], name, feature_args)) {
            break tuple[0];
        }
    } else "";
}

fn pickBackend(cc: Zeson, koishi: Koishi, impl: ?Backend) !struct{Backend, Backend.Params} {
    const b = cc.b;
    const backends = std.enums.values(Backend);
    var backend_map = std.EnumMap(Backend, Backend.Params){};
    defer {
        for (backends) |backend| {
            if (backend_map.get(backend)) |param| {
                if (param.args) |args| b.allocator.free(args);
                b.allocator.free(param.src);
            }
        }
    }
    for (backends) |backend| {
        if (backend.resolve(cc, koishi)) |params| {
            backend_map.put(backend, params);
        }
    }
    if (impl != null) {
        if (backend_map.fetchRemove(impl.?)) |be| {
            return .{impl.?, be};
        }
        if (cc.verbose) {
            std.Progress.lockStdErr();
            defer std.Progress.unlockStdErr();
            std.debug.print("{s} is not supported on this platform\n", .{@tagName(impl.?)});
        }
        return error.BackendNotSupported;
    }
    for (backends) |backend| {
        if (backend_map.fetchRemove(backend)) |be| {
            return .{backend, be};
        }
    }
    if (cc.verbose) {
        std.Progress.lockStdErr();
        defer std.Progress.unlockStdErr();
        std.debug.print("Unsupported platform\n", .{});
    }
    return error.UnsupportedPlatform;
}

const Backend = enum {
    //TODO boost_fcontext,
    emscripten,
    fcontext,
    ucontext,
    ucontext_e2k,
    ucontext_sjlj,
    win32fiber,

    pub const Params = struct {
        src: []const []const u8,
        args: ?[]const []const u8 = null,
    };

    /// Caller owns returned memory
    pub fn resolve(self: Backend, cc: Zeson, koishi: Koishi) ?Params {
        const b = cc.b;
        const target = cc.target;
        const verbose = cc.verbose;
        const upstream = koishi.upstream;
        if (verbose) {
            std.debug.print("Checking backend {s}\n", .{@tagName(self)});
        }
        const result: ?Params = switch (self) {
            .emscripten => res: {
                var fail = false;
                if (cc.sizeof("emscripten_fiber_t", "#include <emscripten/fiber.h>", &.{}) < 0) {
                    fail = true;
                } else {
                    for ([_][]const u8{"emscripten_fiber_init_from_current_context", "emscripten_fiber_swap"}) |fun| {
                        if (!cc.hasFunction(fun, .{.args = feature_args})) {
                            fail = true;
                        }
                    }
                }
                if (fail) break :res null;

                break :res .{
                    .src = b.allocator.dupe([]const u8, &.{b.pathJoin(&.{"src", "emscripten", "emscripten.c"})}) catch @panic("OOM"),
                };
            },
            .fcontext => res: {
                const os = target.result.os.tag;
                const arch = target.result.cpu.arch;
                const fcontext_asm_flavor = "gas";
                const fcontext_asm_suffix = "S";
                const fcontext_binfmt = switch (os) {
                    .macos => "macho",
                    .windows => "pe",
                    .aix => "xcoff",
                    else => "elf",
                };
                var fcontext_abi = switch (os) {
                    .windows => "ms",
                    else => "sysv",
                };
                const fcontext_arch = switch (arch) {
                    .x86 => "i386",
                    .powerpc => "ppc32",
                    .aarch64 => blk: {
                        fcontext_abi = "aapcs";
                        break :blk "arm64";
                    },
                    .arm => blk: {
                        fcontext_abi = "aapcs";
                        break :blk "arm";
                    },
                    .mips => blk: {
                        fcontext_abi = "o32";
                        break :blk "mips32";
                    },
                    .sparc64 => "sparc64",
                    .loongarch64 => "loongarch64",
                    else => @tagName(arch),
                };
                const fcontext_callconv = if (os == .windows and arch == .x86) "__cdecl" else "";
                const fcontext_asm_platform = b.fmt("{s}_{s}_{s}", .{
                    fcontext_arch,
                    fcontext_abi,
                    fcontext_binfmt,
                });

                const fcontext_root = b.pathJoin(&.{"src", "fcontext"});

                var fcontext_src = std.ArrayList([]const u8).init(b.allocator);
                errdefer fcontext_src.deinit();

                fcontext_src.append(b.pathJoin(&.{fcontext_root, "fcontext.c"})) catch @panic("OOM");

                const fcontext_asm_template = b.fmt("{s}_{s}.{s}", .{
                    fcontext_asm_platform,
                    fcontext_asm_flavor,
                    fcontext_asm_suffix,
                });


                // const fcontext_asm_routines = &.{"jump", "make", "ontop"};
                const fcontext_asm_routines: []const []const u8 = &.{"jump", "make"};

                const fcontext_asm_srcdir = b.pathJoin(&.{fcontext_root, "asm"});
                const asmdir_dir = upstream.builder.build_root.handle;
                var dir = asmdir_dir.openDir(fcontext_asm_srcdir, .{}) catch @panic(b.fmt("Failed to open {s}", .{fcontext_asm_srcdir}));
                defer dir.close();

                var fail = false;
                for (fcontext_asm_routines) |routine| {
                    const fname = b.fmt("{s}_{s}", .{routine, fcontext_asm_template});

                    dir.access(fname, .{}) catch {
                        if (verbose) {
                            std.debug.print("fcontext {s} routine implementation missing\n", .{routine});
                        }
                        fail = true;
                    };

                    fcontext_src.append(b.pathJoin(&.{fcontext_asm_srcdir, fname})) catch @panic("OOM");
                }

                if (fail) break :res null;

                const args: []const []const u8 = &.{
                    b.fmt("-DFCONTEXT_CALL={s}", .{fcontext_callconv}),
                };
                break :res .{
                    .src = fcontext_src.toOwnedSlice() catch @panic("OOM"),
                    .args = b.allocator.dupe([]const u8, args) catch @panic("OOM"),
                };
            },
            .ucontext => res: {
                var fail = false;
                if (!cc.hasHeaderSymbol("ucontext.h", "ucontext_t", .{.args = feature_args})) {
                    fail = true;
                } else {
                    for ([_][]const u8{"getcontext", "makecontext", "swapcontext"}) |fun| {
                        if (!cc.hasFunction(fun, .{.args = feature_args})) {
                            fail = true;
                        }
                    }
                }
                if (fail) break :res null;
                break :res .{
                    .src = b.allocator.dupe([]const u8, &.{b.pathJoin(&.{"src", "ucontext", "ucontext.c"})}) catch @panic("OOM"),
                };
            },
            .ucontext_e2k => res: {
                var fail = false;
                for ([_][]const u8{"getcontext", "makecontext_e2k", "swapcontext", "freecontext_e2k"}) |fun| {
                    if (!cc.hasFunction(fun, .{.args = feature_args})) {
                        fail = true;
                    }
                }
                if (fail) break :res null;
                break :res .{
                    .src = b.allocator.dupe([]const u8, &.{b.pathJoin(&.{"src", "ucontext_e2k", "ucontext_e2k.c"})}) catch @panic("OOM"),
                };
            },
            .ucontext_sjlj => res: {
                var fail = false;
                if (koishi.sjlj.len == 0 or !cc.hasHeaderSymbol("ucontext.h", "ucontext_t", .{.args = feature_args})) {
                    fail = true;
                } else {
                    for ([_][]const u8{"getcontext", "setcontext", "makecontext", "swapcontext"}) |fun| {
                        if (!cc.hasFunction(fun, .{.args = feature_args})) {
                            fail = true;
                        }
                    }
                }
                if (fail) break :res null;
                break :res .{
                    .src = b.allocator.dupe([]const u8, &.{b.pathJoin(&.{"src", "ucontext_sjlj", "ucontext_sjlj.c"})}) catch @panic("OOM"),
                    .args = b.allocator.dupe([]const u8, &.{"-U_FORTIFY_SOURCE"}) catch @panic("OOM"), // avoid longjmp false positives
                };
            },
            .win32fiber => res: {
                break :res if (target.result.os.tag == .windows) .{
                    .src = b.allocator.dupe([]const u8, &.{b.pathJoin(&.{"src", "win32fiber", "win32fiber.c"})}) catch @panic("OOM"),
                } else null;
            }
        };
        if (verbose) {
            std.debug.print("Backend {s} is {s}supported\n", .{@tagName(self), if (result == null) "not " else ""});
        }
        return result;
    }
};