const std = @import("std");
const argonaut = @import("argonaut");
const voidbox = @import("voidbox");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const parser = try argonaut.newParser(allocator, "vb", "voidbox CLI frontend");
    defer parser.deinit();

    const run_cmd = try parser.newCommand("run", "Launch a sandboxed command");
    const doctor_cmd = try parser.newCommand("doctor", "Check host support and readiness");

    var rootfs_opts: argonaut.Options = .{ .help = "Sandbox rootfs path", .default_string = "/" };
    const rootfs = try run_cmd.string("r", "rootfs", &rootfs_opts);
    var name_opts: argonaut.Options = .{ .help = "Sandbox name", .default_string = "sandbox" };
    const name = try run_cmd.string("n", "name", &name_opts);
    var cmd_opts: argonaut.Options = .{ .help = "Command line to execute", .default_string = "" };
    const cmd = try run_cmd.string("c", "cmd", &cmd_opts);

    const unshare_all = try run_cmd.flag("", "unshare-all", null);
    const share_net = try run_cmd.flag("", "share-net", null);
    const unshare_user = try run_cmd.flag("", "unshare-user", null);
    const unshare_net = try run_cmd.flag("", "unshare-net", null);
    const unshare_mount = try run_cmd.flag("", "unshare-mount", null);
    const unshare_pid = try run_cmd.flag("", "unshare-pid", null);
    const unshare_uts = try run_cmd.flag("", "unshare-uts", null);
    const unshare_ipc = try run_cmd.flag("", "unshare-ipc", null);
    const unshare_cgroup = try run_cmd.flag("", "unshare-cgroup", null);

    var userns_fd_opts: argonaut.Options = .{ .help = "Existing user namespace fd", .default_int = -1 };
    const userns_fd = try run_cmd.int("", "userns", &userns_fd_opts);
    var userns2_fd_opts: argonaut.Options = .{ .help = "Late-stage user namespace fd", .default_int = -1 };
    const userns2_fd = try run_cmd.int("", "userns2", &userns2_fd_opts);
    var pidns_fd_opts: argonaut.Options = .{ .help = "Existing pid namespace fd", .default_int = -1 };
    const pidns_fd = try run_cmd.int("", "pidns", &pidns_fd_opts);
    var netns_fd_opts: argonaut.Options = .{ .help = "Existing net namespace fd", .default_int = -1 };
    const netns_fd = try run_cmd.int("", "netns", &netns_fd_opts);
    var mntns_fd_opts: argonaut.Options = .{ .help = "Existing mount namespace fd", .default_int = -1 };
    const mntns_fd = try run_cmd.int("", "mntns", &mntns_fd_opts);
    var utsns_fd_opts: argonaut.Options = .{ .help = "Existing uts namespace fd", .default_int = -1 };
    const utsns_fd = try run_cmd.int("", "utsns", &utsns_fd_opts);
    var ipcns_fd_opts: argonaut.Options = .{ .help = "Existing ipc namespace fd", .default_int = -1 };
    const ipcns_fd = try run_cmd.int("", "ipcns", &ipcns_fd_opts);

    const disable_userns = try run_cmd.flag("", "disable-userns", null);
    const assert_userns_disabled = try run_cmd.flag("", "assert-userns-disabled", null);

    var uid_opts: argonaut.Options = .{ .help = "UID inside sandbox", .default_int = -1 };
    const uid = try run_cmd.int("", "uid", &uid_opts);
    var gid_opts: argonaut.Options = .{ .help = "GID inside sandbox", .default_int = -1 };
    const gid = try run_cmd.int("", "gid", &gid_opts);
    var hostname_opts: argonaut.Options = .{ .help = "Hostname inside sandbox", .default_string = "" };
    const hostname = try run_cmd.string("", "hostname", &hostname_opts);
    const as_pid_1 = try run_cmd.flag("", "as-pid-1", null);

    const clearenv = try run_cmd.flag("", "clearenv", null);
    var setenv_opts: argonaut.Options = .{ .help = "Set environment KEY=VALUE entries (comma-separated)", .default_string = "" };
    const setenv = try run_cmd.string("", "setenv", &setenv_opts);
    var unsetenv_opts: argonaut.Options = .{ .help = "Unset environment keys (comma-separated)", .default_string = "" };
    const unsetenv = try run_cmd.string("", "unsetenv", &unsetenv_opts);
    var chdir_opts: argonaut.Options = .{ .help = "Working directory", .default_string = "" };
    const chdir = try run_cmd.string("", "chdir", &chdir_opts);
    var argv0_opts: argonaut.Options = .{ .help = "Override argv[0]", .default_string = "" };
    const argv0 = try run_cmd.string("", "argv0", &argv0_opts);
    const new_session = try run_cmd.flag("", "new-session", null);
    const die_with_parent = try run_cmd.flag("", "die-with-parent", null);

    var mem_opts: argonaut.Options = .{ .help = "memory.max value", .default_string = "" };
    const mem = try run_cmd.string("", "mem", &mem_opts);
    var cpu_opts: argonaut.Options = .{ .help = "cpu.max value", .default_string = "" };
    const cpu = try run_cmd.string("", "cpu", &cpu_opts);
    var pids_opts: argonaut.Options = .{ .help = "pids.max value", .default_string = "" };
    const pids = try run_cmd.string("", "pids", &pids_opts);

    const no_new_privs = try run_cmd.flag("", "no-new-privs", null);
    var cap_add_opts: argonaut.Options = .{ .help = "Capabilities to add (comma-separated names or IDs)", .default_string = "" };
    const cap_add = try run_cmd.string("", "cap-add", &cap_add_opts);
    var cap_drop_opts: argonaut.Options = .{ .help = "Capabilities to drop (comma-separated names or IDs)", .default_string = "" };
    const cap_drop = try run_cmd.string("", "cap-drop", &cap_drop_opts);
    var seccomp_fd_opts: argonaut.Options = .{ .help = "Primary seccomp filter fd", .default_int = -1 };
    const seccomp_fd = try run_cmd.int("", "seccomp", &seccomp_fd_opts);
    var seccomp_add_fds_opts: argonaut.Options = .{ .help = "Additional seccomp filter fds (comma-separated)", .default_string = "" };
    const seccomp_add_fds = try run_cmd.string("", "add-seccomp-fd", &seccomp_add_fds_opts);

    var json_status_fd_opts: argonaut.Options = .{ .help = "JSON status output fd", .default_int = -1 };
    const json_status_fd = try run_cmd.int("", "json-status-fd", &json_status_fd_opts);
    var info_fd_opts: argonaut.Options = .{ .help = "Info output fd", .default_int = -1 };
    const info_fd = try run_cmd.int("", "info-fd", &info_fd_opts);
    var sync_fd_opts: argonaut.Options = .{ .help = "Sync fd", .default_int = -1 };
    const sync_fd = try run_cmd.int("", "sync-fd", &sync_fd_opts);
    var block_fd_opts: argonaut.Options = .{ .help = "Block fd", .default_int = -1 };
    const block_fd = try run_cmd.int("", "block-fd", &block_fd_opts);
    var userns_block_fd_opts: argonaut.Options = .{ .help = "Userns block fd", .default_int = -1 };
    const userns_block_fd = try run_cmd.int("", "userns-block-fd", &userns_block_fd_opts);
    var lock_file_opts: argonaut.Options = .{ .help = "Lock file path", .default_string = "" };
    const lock_file = try run_cmd.string("", "lock-file", &lock_file_opts);

    var actions_opts: argonaut.Options = .{ .help = "Ordered filesystem action tokens (comma-separated)", .default_string = "" };
    const actions = try run_cmd.string("", "action", &actions_opts);

    const doctor_json = try doctor_cmd.flag("", "json", null);
    const doctor_strict = try doctor_cmd.flag("", "strict", null);

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    parser.parse(args) catch {
        const usage_text = try parser.usage(null);
        defer allocator.free(usage_text);
        std.debug.print("{s}", .{usage_text});
        std.posix.exit(2);
    };

    if (doctor_cmd.happened) {
        const report = try voidbox.check_host(allocator);
        const out = std.fs.File.stdout().deprecatedWriter();
        if (doctor_json.*) {
            try report.printJson(out);
        } else {
            try report.print(out);
        }
        if (doctor_strict.* and !report.strictReady()) std.posix.exit(1);
        return;
    }

    if (!run_cmd.happened) {
        const usage_text = try parser.usage(null);
        defer allocator.free(usage_text);
        std.debug.print("{s}", .{usage_text});
        std.posix.exit(2);
    }

    const parsed_cmd = try parseWords(allocator, cmd.*);
    defer allocator.free(parsed_cmd);

    var cfg: voidbox.JailConfig = .{
        .name = name.*,
        .rootfs_path = rootfs.*,
        .cmd = if (parsed_cmd.len == 0) &.{"/bin/sh"} else parsed_cmd,
        .resources = .{
            .mem = nonEmpty(mem.*),
            .cpu = nonEmpty(cpu.*),
            .pids = nonEmpty(pids.*),
        },
        .isolation = .{
            .user = false,
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
        .security = .{
            .no_new_privs = no_new_privs.*,
            .disable_userns = disable_userns.*,
            .assert_userns_disabled = assert_userns_disabled.*,
        },
        .process = .{
            .chdir = nonEmpty(chdir.*),
            .argv0 = nonEmpty(argv0.*),
            .clear_env = clearenv.*,
            .new_session = new_session.*,
            .die_with_parent = die_with_parent.*,
        },
        .runtime = .{
            .uid = if (uid.* >= 0) @intCast(uid.*) else null,
            .gid = if (gid.* >= 0) @intCast(gid.*) else null,
            .hostname = nonEmpty(hostname.*),
            .as_pid_1 = as_pid_1.*,
        },
        .status = .{
            .json_status_fd = if (json_status_fd.* >= 0) @intCast(json_status_fd.*) else null,
            .info_fd = if (info_fd.* >= 0) @intCast(info_fd.*) else null,
            .sync_fd = if (sync_fd.* >= 0) @intCast(sync_fd.*) else null,
            .block_fd = if (block_fd.* >= 0) @intCast(block_fd.*) else null,
            .userns_block_fd = if (userns_block_fd.* >= 0) @intCast(userns_block_fd.*) else null,
            .lock_file_path = nonEmpty(lock_file.*),
        },
    };

    if (unshare_all.*) {
        cfg.isolation = .{ .user = true, .net = true, .mount = true, .pid = true, .uts = true, .ipc = true, .cgroup = true };
    }
    if (unshare_user.*) cfg.isolation.user = true;
    if (unshare_net.*) cfg.isolation.net = true;
    if (unshare_mount.*) cfg.isolation.mount = true;
    if (unshare_pid.*) cfg.isolation.pid = true;
    if (unshare_uts.*) cfg.isolation.uts = true;
    if (unshare_ipc.*) cfg.isolation.ipc = true;
    if (unshare_cgroup.*) cfg.isolation.cgroup = true;
    if (share_net.*) cfg.isolation.net = false;

    cfg.namespace_fds = .{
        .user = toOptFd(userns_fd.*),
        .user2 = toOptFd(userns2_fd.*),
        .pid = toOptFd(pidns_fd.*),
        .net = toOptFd(netns_fd.*),
        .mount = toOptFd(mntns_fd.*),
        .uts = toOptFd(utsns_fd.*),
        .ipc = toOptFd(ipcns_fd.*),
    };

    var set_env_entries = std.ArrayList(voidbox.EnvironmentEntry).empty;
    defer set_env_entries.deinit(allocator);
    var setenv_it = splitComma(setenv.*);
    while (setenv_it.next()) |kv| {
        try set_env_entries.append(allocator, try parseEnv(kv));
    }
    cfg.process.set_env = try set_env_entries.toOwnedSlice(allocator);

    var unset_env_entries = std.ArrayList([]const u8).empty;
    defer unset_env_entries.deinit(allocator);
    var unsetenv_it = splitComma(unsetenv.*);
    while (unsetenv_it.next()) |key| {
        try unset_env_entries.append(allocator, key);
    }
    cfg.process.unset_env = try unset_env_entries.toOwnedSlice(allocator);

    var cap_add_ids = std.ArrayList(u8).empty;
    defer cap_add_ids.deinit(allocator);
    var cap_add_it = splitComma(cap_add.*);
    while (cap_add_it.next()) |raw| {
        try cap_add_ids.append(allocator, try parseCapability(raw));
    }
    cfg.security.cap_add = try cap_add_ids.toOwnedSlice(allocator);

    var cap_drop_ids = std.ArrayList(u8).empty;
    defer cap_drop_ids.deinit(allocator);
    var cap_drop_it = splitComma(cap_drop.*);
    while (cap_drop_it.next()) |raw| {
        try cap_drop_ids.append(allocator, try parseCapability(raw));
    }
    cfg.security.cap_drop = try cap_drop_ids.toOwnedSlice(allocator);

    var seccomp_fds = std.ArrayList(i32).empty;
    defer seccomp_fds.deinit(allocator);
    if (seccomp_fd.* >= 0) try seccomp_fds.append(allocator, @intCast(seccomp_fd.*));
    var seccomp_extra_it = splitComma(seccomp_add_fds.*);
    while (seccomp_extra_it.next()) |fd_raw| {
        const fd = try std.fmt.parseInt(i64, fd_raw, 10);
        if (fd >= 0) try seccomp_fds.append(allocator, @intCast(fd));
    }
    cfg.security.seccomp_filter_fds = try seccomp_fds.toOwnedSlice(allocator);

    var fs_actions = std.ArrayList(voidbox.FsAction).empty;
    defer fs_actions.deinit(allocator);
    var actions_it = splitComma(actions.*);
    while (actions_it.next()) |token| {
        try fs_actions.append(allocator, try parseAction(token));
    }
    cfg.fs_actions = try fs_actions.toOwnedSlice(allocator);

    const outcome = try voidbox.launch(cfg, allocator);
    std.posix.exit(outcome.exit_code);
}

fn nonEmpty(s: []const u8) ?[]const u8 {
    return if (s.len == 0) null else s;
}

fn toOptFd(v: i64) ?i32 {
    return if (v < 0) null else @intCast(v);
}

fn parseWords(allocator: std.mem.Allocator, s: []const u8) ![]const []const u8 {
    var out = std.ArrayList([]const u8).empty;
    defer out.deinit(allocator);

    var it = std.mem.tokenizeAny(u8, s, " \t\r\n");
    while (it.next()) |token| {
        try out.append(allocator, token);
    }

    return out.toOwnedSlice(allocator);
}

fn splitComma(s: []const u8) std.mem.TokenIterator(u8, .scalar) {
    return std.mem.tokenizeScalar(u8, s, ',');
}

fn parseEnv(kv: []const u8) !voidbox.EnvironmentEntry {
    const i = std.mem.indexOfScalar(u8, kv, '=') orelse return error.InvalidSetEnv;
    if (i == 0) return error.InvalidSetEnv;
    return .{ .key = kv[0..i], .value = kv[i + 1 ..] };
}

fn parseCapability(raw: []const u8) !u8 {
    return std.fmt.parseInt(u8, raw, 10) catch {
        if (std.ascii.eqlIgnoreCase(raw, "NET_RAW") or std.ascii.eqlIgnoreCase(raw, "CAP_NET_RAW")) return std.os.linux.CAP.NET_RAW;
        if (std.ascii.eqlIgnoreCase(raw, "NET_ADMIN") or std.ascii.eqlIgnoreCase(raw, "CAP_NET_ADMIN")) return std.os.linux.CAP.NET_ADMIN;
        if (std.ascii.eqlIgnoreCase(raw, "SYS_ADMIN") or std.ascii.eqlIgnoreCase(raw, "CAP_SYS_ADMIN")) return std.os.linux.CAP.SYS_ADMIN;
        if (std.ascii.eqlIgnoreCase(raw, "SETUID") or std.ascii.eqlIgnoreCase(raw, "CAP_SETUID")) return std.os.linux.CAP.SETUID;
        if (std.ascii.eqlIgnoreCase(raw, "SETGID") or std.ascii.eqlIgnoreCase(raw, "CAP_SETGID")) return std.os.linux.CAP.SETGID;
        return error.InvalidCapability;
    };
}

fn parseAction(token: []const u8) !voidbox.FsAction {
    var it = std.mem.splitScalar(u8, token, ':');
    const kind = it.next() orelse return error.InvalidAction;

    if (std.mem.eql(u8, kind, "perms")) {
        const mode = it.next() orelse return error.InvalidAction;
        return .{ .perms = try std.fmt.parseInt(u32, mode, 8) };
    }
    if (std.mem.eql(u8, kind, "size")) {
        const size = it.next() orelse return error.InvalidAction;
        return .{ .size = try std.fmt.parseInt(usize, size, 10) };
    }

    const a = it.next() orelse return error.InvalidAction;
    const b = it.next();
    const c = it.next();
    const d = it.next();

    if (std.mem.eql(u8, kind, "bind")) return .{ .bind = .{ .src = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "bind_try")) return .{ .bind_try = .{ .src = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "dev_bind")) return .{ .dev_bind = .{ .src = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "dev_bind_try")) return .{ .dev_bind_try = .{ .src = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "ro_bind")) return .{ .ro_bind = .{ .src = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "ro_bind_try")) return .{ .ro_bind_try = .{ .src = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "remount_ro")) return .{ .remount_ro = a };
    if (std.mem.eql(u8, kind, "proc")) return .{ .proc = a };
    if (std.mem.eql(u8, kind, "dev")) return .{ .dev = a };
    if (std.mem.eql(u8, kind, "mqueue")) return .{ .mqueue = a };
    if (std.mem.eql(u8, kind, "tmpfs")) return .{ .tmpfs = .{ .dest = a } };
    if (std.mem.eql(u8, kind, "dir")) return .{ .dir = .{ .path = a, .mode = if (b) |m| try std.fmt.parseInt(u32, m, 8) else null } };
    if (std.mem.eql(u8, kind, "symlink")) return .{ .symlink = .{ .target = a, .path = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "chmod")) return .{ .chmod = .{ .path = b orelse return error.InvalidAction, .mode = try std.fmt.parseInt(u32, a, 8) } };
    if (std.mem.eql(u8, kind, "overlay_src")) return .{ .overlay_src = .{ .key = a, .path = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "overlay")) return .{ .overlay = .{ .source_key = a, .upper = b orelse return error.InvalidAction, .work = c orelse return error.InvalidAction, .dest = d orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "tmp_overlay")) return .{ .tmp_overlay = .{ .source_key = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "ro_overlay")) return .{ .ro_overlay = .{ .source_key = a, .dest = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "bind_data")) return .{ .bind_data = .{ .dest = a, .data = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "ro_bind_data")) return .{ .ro_bind_data = .{ .dest = a, .data = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "file")) return .{ .file = .{ .path = a, .data = b orelse return error.InvalidAction } };
    if (std.mem.eql(u8, kind, "bind_data_fd")) return .{ .bind_data_fd = .{ .dest = a, .fd = @intCast(try std.fmt.parseInt(i32, b orelse return error.InvalidAction, 10)) } };
    if (std.mem.eql(u8, kind, "ro_bind_data_fd")) return .{ .ro_bind_data_fd = .{ .dest = a, .fd = @intCast(try std.fmt.parseInt(i32, b orelse return error.InvalidAction, 10)) } };
    if (std.mem.eql(u8, kind, "file_fd")) return .{ .file_fd = .{ .path = a, .fd = @intCast(try std.fmt.parseInt(i32, b orelse return error.InvalidAction, 10)) } };

    return error.InvalidAction;
}
