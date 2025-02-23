// This file implements parts the meson C compiler scanning logic
// Meson is Copyright (c) The Meson development team, licensed under Apache 2.0
const std = @import("std");
const Zeson = @This();

b: *std.Build,
target: std.Build.ResolvedTarget,
verbose: bool,
tmp_dir: []const u8,

pub fn hasFunction(cc: Zeson, func_name: []const u8, arg: struct {
    prefix: []const u8 = "",
    args: []const []const u8 = &.{},
}) bool {
    std.Progress.lockStdErr();
    defer std.Progress.unlockStdErr();
    const prefix, const args = .{arg.prefix, arg.args};
    const b = cc.b;
    var arena = std.heap.ArenaAllocator.init(b.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const stubs_fail =
        \\
        \\#if defined __stub_{func} || defined __stub___{func}
        \\fail fail fail this function is not going to work
        \\#endif
        \\
    ;
    const head, const main = if (std.mem.containsAtLeast(u8, prefix, 1, "#include"))
        .{ have_prototype_templ.head, have_prototype_templ.main }
    else
        .{ no_prototype_templ.head, have_prototype_templ.main };

    var templ = std.mem.concat(allocator, u8, &.{ head, stubs_fail, main }) catch @panic("OOM");
    templ = std.mem.replaceOwned(u8, allocator, templ, "{func}", func_name) catch @panic("OOM");
    templ = std.mem.replaceOwned(u8, allocator, templ, "{prefix}", prefix) catch @panic("OOM");
    const verbose = cc.verbose;
    const logger = if (verbose) Logger.create() else undefined;
    if (verbose) {
        logger.write("Checking for function \"");
        logger.bold(func_name);
        logger.write("\" : ");
    }
    const result = cc.compile(templ, args);
    if (verbose) {
        logger.success(result);
        logger.write("\n");
    }
    return result;
}

pub fn hasHeaderSymbol(cc: Zeson, hname: []const u8, symbol: []const u8, arg: struct {
    prefix: []const u8 = "",
    args: []const []const u8 = &.{},
}) bool {
    std.Progress.lockStdErr();
    defer std.Progress.unlockStdErr();
    const prefix, const args = .{ arg.prefix, arg.args };
    const b = cc.b;
    const str = std.fmt.allocPrint(b.allocator,
        \\{2s}
        \\#include <{0s}>
        \\int main(void) {{
        \\  #ifndef {1s}
        \\    {1s};
        \\  #endif
        \\  return 0;
        \\}}
        \\
    , .{ hname, symbol, prefix }) catch @panic("OOM");
    defer b.allocator.free(str);
    const verbose = cc.verbose;
    const logger = if (verbose) Logger.create() else undefined;
    if (verbose) {
        logger.write("Header \"");
        logger.bold(hname);
        logger.write("\" has symbol \"");
        logger.bold(symbol);
        logger.write("\" : ");
    }
    const result = cc.compile(str, args);
    if (verbose) {
        logger.success(result);
        logger.write("\n");
    }
    return result;
}

pub fn links(cc: Zeson, src: []const u8, name: []const u8, args: []const []const u8) bool {
    std.Progress.lockStdErr();
    defer std.Progress.unlockStdErr();
    const verbose = cc.verbose;
    const logger = if (verbose) Logger.create() else undefined;
    if (verbose) {
        logger.write("Checking if \"");
        logger.bold(name);
        logger.write("\" : links: ");
    }
    const result = cc.compile(src, args);
    if (verbose) {
        logger.success(result);
        logger.write("\n");
    }
    return result;
}

pub fn sizeof(cc: Zeson, typename: []const u8, prefix: []const u8, args: []const []const u8) i32 {
    const expression = std.fmt.allocPrint(cc.b.allocator, "sizeof({s})", .{typename}) catch @panic("OOM");
    defer cc.b.allocator.free(expression);
    return cc.crossComputeInt(prefix, expression, args);
}

fn recycleAllocPrint(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype, out: *?[]const u8) []u8 {
    if (out.*) |buf| {
        allocator.free(buf);
    }
    const result = std.fmt.allocPrint(allocator, fmt, args) catch @panic("OOM");
    out.* = result;
    return result;
}

fn crossComputeInt(cc: Zeson, prefix: []const u8, expression: []const u8, args: []const []const u8) i32 {
    const b = cc.b;
    var buf: ?[]const u8 = null;
    defer {
        if (buf) |buff| b.allocator.free(buff);
    }
    const maxInt = std.math.maxInt(i32);
    const minInt = std.math.minInt(i32);
    var low: i32 = undefined;
    var high: i32 = undefined;
    var cur: i32 = undefined;
    if (cc.compileInt(prefix, recycleAllocPrint(b.allocator, "{s} >= 0", .{expression}, &buf), args)) {
        low = 0;
        cur = 0;
        while (cc.compileInt(prefix, recycleAllocPrint(b.allocator, "{s} > {}", .{expression, cur}, &buf), args)) {
            low = cur + 1;
            if (low > maxInt) {
                if (cc.verbose) {
                    std.Progress.lockStdErr();
                    defer std.Progress.unlockStdErr();
                    std.debug.print("Cross-compile check overflowed\n", .{});
                }
                return error.Overflow;
            }
            cur = @min(cur * 2 + 1, maxInt);
        }
        high = cur;
    } else {
        high = -1;
        cur = -1;

        while (cc.compileInt(prefix, recycleAllocPrint(b.allocator, "{s} < {}", .{expression, cur}, &buf), args)) {
            high = cur - 1;
            if (high < minInt) {
                if (cc.verbose) {
                    std.Progress.lockStdErr();
                    defer std.Progress.unlockStdErr();
                    std.debug.print("Cross-compile check overflowed\n", .{});
                }
                return error.Overflow;
            }
            cur = @max(cur * 2, minInt);
        }
        low = cur;
    }

    while (low != high) {
        cur = low + @divFloor(high - low, 2);
        if (cc.compileInt(prefix, recycleAllocPrint(b.allocator, "{s} <= {}", .{expression, cur}, &buf), args)) {
            high = cur;
        } else {
            low = cur + 1;
        }
    }

    return low;
}

fn compileInt(cc: Zeson, prefix: []const u8, expression: []const u8, args: []const []const u8) bool {
    const b = cc.b;
    const src = std.fmt.allocPrint(b.allocator,
        \\
        \\{s}
        \\#include <stddef.h>
        \\int main(void) {{ static int a[1-2*!({s})]; a[0]=0; return 0;}}
        \\
    , .{prefix, expression}) catch @panic("OOM");
    defer b.allocator.free(src);
    return cc.compile(src, args);
}

fn compile(cc: Zeson, src: []const u8, args: []const []const u8) bool {
    const b = cc.b;
    const target = cc.target;
    var arena = std.heap.ArenaAllocator.init(b.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const targetStr = target.result.linuxTriple(allocator) catch @panic("OOM");
    const argv = std.mem.concat(allocator, []const u8, &.{ &.{ b.graph.zig_exe, "cc", "-target", targetStr }, args, &.{ "-xc", "src.c", "-o-" } }) catch @panic("OOM");
    var child = std.process.Child.init(argv, allocator);
    std.fs.deleteTreeAbsolute(cc.tmp_dir) catch |e| @panic(b.fmt("Failed to delete tmpdir: {s}\n", .{@errorName(e)}));
    std.fs.makeDirAbsolute(cc.tmp_dir) catch |e| @panic(b.fmt("Failed to create tmpdir: {s}\n", .{@errorName(e)}));
    var dir = std.fs.openDirAbsolute(cc.tmp_dir, .{}) catch |e| @panic(b.fmt("Failed to open tmpdir: {s}\n", .{@errorName(e)}));
    defer {
        dir.close();
        std.fs.deleteTreeAbsolute(cc.tmp_dir) catch {};
    }
    {
        const src_file = dir.createFile("src.c", .{}) catch |e| @panic(b.fmt("Failed to create src file: {s}\n", .{@errorName(e)}));
        defer src_file.close();
        src_file.writeAll(src) catch |e| @panic(b.fmt("Failed to write src file: {s}\n", .{@errorName(e)}));
    }
    child.cwd = cc.tmp_dir;
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch |err| @panic(@errorName(err));
    errdefer {
        _ = child.kill() catch {};
    }
    const term = child.wait() catch |err| @panic(@errorName(err));
    if (term != .Exited) {
        return false;
    }
    return term.Exited == 0;
}

const Templ = struct { head: []const u8, main: []const u8 };

const no_prototype_templ = Templ{ .head = 
\\
\\#define {func} zeson_disable_define_of{func}
\\{prefix}
\\#include <limits.h>
\\#undef {func}
\\#ifdef __cplusplus
\\extern "C"
\\#endif
\\char {func} (void);
\\
, .main = 
\\
\\int main(void) {
\\  return {func} ();
\\}
\\
};

const have_prototype_templ = Templ{ .head = 
\\{prefix}
\\#include <limits.h>
\\
, .main = 
\\
\\int main(void) {
\\  void *a = (void*) &{func};
\\  long long b = (long long) a;
\\  return (int) b;
\\}
\\
};


const Logger = struct {
    file: std.fs.File,
    tty_config: std.io.tty.Config,
    pub fn create() Logger {
        const stderr = std.io.getStdErr();
        return .{
            .file = stderr,
            .tty_config = std.io.tty.detectConfig(stderr),
        };
    }

    pub fn write(logger: Logger, bytes: []const u8) void {
        logger.file.writeAll(bytes) catch {};
    }

    pub fn bold(logger: Logger, bytes: []const u8) void {
        logger.tty_config.setColor(logger.file, .bold) catch {};
        logger.write(bytes);
        logger.tty_config.setColor(logger.file, .reset) catch {};
    }

    pub fn success(logger: Logger, result: bool) void {
        logger.tty_config.setColor(logger.file, .bold) catch {};
        const color: std.io.tty.Color, const text = if (result) .{.green, "YES"} else .{.red, "NO"};
        logger.tty_config.setColor(logger.file, color) catch {};
        logger.write(text);
        logger.tty_config.setColor(logger.file, .reset) catch {};
    }
};