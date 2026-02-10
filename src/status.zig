const std = @import("std");

pub fn emitJson(fd: i32, event: []const u8, pid: std.posix.pid_t, exit_code: ?u8) !void {
    var file = std.fs.File{ .handle = fd };
    var writer = file.deprecatedWriter();

    if (exit_code) |code| {
        try writer.print("{{\"event\":\"{s}\",\"pid\":{},\"exit_code\":{}}}\n", .{ event, pid, code });
    } else {
        try writer.print("{{\"event\":\"{s}\",\"pid\":{}}}\n", .{ event, pid });
    }
}
