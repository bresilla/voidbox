const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const c = @cImport(@cInclude("signal.h"));

const namespace = @import("namespace.zig");
const namespace_sequence = @import("namespace_sequence.zig");
const caps = @import("caps.zig");
const seccomp = @import("seccomp.zig");
const ProcessOptions = @import("config.zig").ProcessOptions;
const SecurityOptions = @import("config.zig").SecurityOptions;
const NamespaceFds = @import("config.zig").NamespaceFds;

pub fn prepare(
    allocator: std.mem.Allocator,
    uid: linux.uid_t,
    gid: linux.gid_t,
    process: ProcessOptions,
    security: SecurityOptions,
    namespace_fds: NamespaceFds,
) !void {
    try checkErr(linux.setreuid(uid, uid), error.UID);
    try checkErr(linux.setregid(gid, gid), error.GID);

    try namespace_sequence.attachInitial(namespace_fds);

    if (security.disable_userns or security.assert_userns_disabled) {
        try namespace.assertUserNsDisabled();
    }

    if (process.new_session and !std.posix.isatty(std.posix.STDIN_FILENO)) {
        _ = std.posix.setsid() catch return error.SetSidFailed;
    }
    if (process.die_with_parent) {
        try checkErr(linux.prctl(@intFromEnum(linux.PR.SET_PDEATHSIG), @as(usize, @intCast(c.SIGKILL)), 0, 0, 0), error.PrctlFailed);
    }
    if (security.no_new_privs) {
        try checkErr(linux.prctl(@intFromEnum(linux.PR.SET_NO_NEW_PRIVS), 1, 0, 0, 0), error.NoNewPrivsFailed);
    }

    try caps.apply(security);
    try seccomp.apply(security, allocator);
}

pub fn finalizeNamespaces(namespace_fds: NamespaceFds) !void {
    try namespace_sequence.attachUserNs2(namespace_fds);
}

pub fn exec(
    allocator: std.mem.Allocator,
    cmd: []const []const u8,
    process: ProcessOptions,
) !void {
    var exec_cmd = cmd;
    var owns_exec_cmd = false;
    if (process.argv0) |argv0| {
        const cmd_copy = try allocator.alloc([]const u8, cmd.len);
        @memcpy(cmd_copy, cmd);
        cmd_copy[0] = argv0;
        exec_cmd = cmd_copy;
        owns_exec_cmd = true;
    }
    defer if (owns_exec_cmd) allocator.free(exec_cmd);

    var env_map = if (process.clear_env)
        std.process.EnvMap.init(allocator)
    else
        try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    for (process.unset_env) |key| {
        env_map.remove(key);
    }
    for (process.set_env) |entry| {
        try env_map.put(entry.key, entry.value);
    }

    std.process.execve(allocator, exec_cmd, &env_map) catch return error.CmdFailed;
}
