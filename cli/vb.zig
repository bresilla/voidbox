const std = @import("std");
const voidbox = @import("voidbox");

const Parsed = struct {
    cfg: voidbox.JailConfig,
    cmd: []const []const u8,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    if (argv.len >= 2 and std.mem.eql(u8, argv[1], "doctor")) {
        try runDoctor(allocator, argv[2..]);
        return;
    }

    const parsed = parseBwrapArgs(allocator, argv[1..]) catch |err| {
        try printCliError(err);
        try printUsage();
        std.posix.exit(2);
    };
    defer allocator.free(parsed.cmd);

    voidbox.validate(parsed.cfg) catch |err| {
        std.debug.print("validation failed: {s}\n", .{@errorName(err)});
        std.posix.exit(2);
    };

    const outcome = voidbox.launch(parsed.cfg, allocator) catch |err| {
        std.debug.print("launch failed: {s}\n", .{@errorName(err)});
        std.debug.print("hint: run `vb doctor` for host diagnostics\n", .{});
        std.posix.exit(1);
    };
    std.posix.exit(outcome.exit_code);
}

fn runDoctor(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var as_json = false;
    var strict = false;

    for (args) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            as_json = true;
        } else if (std.mem.eql(u8, arg, "--strict")) {
            strict = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            std.debug.print("usage: vb doctor [--json] [--strict]\n", .{});
            return;
        } else {
            return error.UnknownOption;
        }
    }

    const report = try voidbox.check_host(allocator);
    const out = std.fs.File.stdout().deprecatedWriter();
    if (as_json) {
        try report.printJson(out);
    } else {
        try report.print(out);
    }
    if (strict and !report.strictReady()) {
        std.posix.exit(1);
    }
}

fn parseBwrapArgs(allocator: std.mem.Allocator, raw: []const []const u8) !Parsed {
    if (raw.len == 0) return error.HelpRequested;

    var cfg: voidbox.JailConfig = .{
        .name = "sandbox",
        .rootfs_path = "/",
        .cmd = &.{"/bin/sh"},
        .isolation = .{
            .user = false,
            .net = false,
            .mount = false,
            .pid = false,
            .uts = false,
            .ipc = false,
            .cgroup = false,
        },
    };

    var pending_mode: ?u32 = null;
    var pending_size: ?usize = null;
    var overlay_key_index: usize = 0;
    var latest_overlay_key: ?[]const u8 = null;

    var fs_actions = std.ArrayList(voidbox.FsAction).empty;
    defer fs_actions.deinit(allocator);

    var env_set = std.ArrayList(voidbox.EnvironmentEntry).empty;
    defer env_set.deinit(allocator);

    var env_unset = std.ArrayList([]const u8).empty;
    defer env_unset.deinit(allocator);

    var cap_add = std.ArrayList(u8).empty;
    defer cap_add.deinit(allocator);

    var cap_drop = std.ArrayList(u8).empty;
    defer cap_drop.deinit(allocator);

    var seccomp_fds = std.ArrayList(i32).empty;
    defer seccomp_fds.deinit(allocator);

    var command = std.ArrayList([]const u8).empty;
    defer command.deinit(allocator);

    var i: usize = 0;
    while (i < raw.len) : (i += 1) {
        const arg = raw[i];

        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < raw.len) : (i += 1) {
                try command.append(allocator, raw[i]);
            }
            break;
        }

        if (!std.mem.startsWith(u8, arg, "--")) {
            while (i < raw.len) : (i += 1) {
                try command.append(allocator, raw[i]);
            }
            break;
        }

        if (std.mem.eql(u8, arg, "--help")) return error.HelpRequested;
        if (std.mem.eql(u8, arg, "--version")) {
            std.debug.print("vb 0.0.1\n", .{});
            std.posix.exit(0);
        }
        if (std.mem.eql(u8, arg, "--level-prefix")) continue;
        if (std.mem.eql(u8, arg, "--args")) {
            _ = try nextArg(raw, &i, "--args");
            continue;
        }

        if (std.mem.eql(u8, arg, "--unshare-all")) {
            cfg.isolation.user = true;
            cfg.isolation.ipc = true;
            cfg.isolation.pid = true;
            cfg.isolation.net = true;
            cfg.isolation.uts = true;
            cfg.isolation.cgroup = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--share-net")) {
            cfg.isolation.net = false;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-user") or std.mem.eql(u8, arg, "--unshare-user-try")) {
            cfg.isolation.user = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-ipc")) {
            cfg.isolation.ipc = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-pid")) {
            cfg.isolation.pid = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-net")) {
            cfg.isolation.net = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-uts")) {
            cfg.isolation.uts = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--unshare-cgroup") or std.mem.eql(u8, arg, "--unshare-cgroup-try")) {
            cfg.isolation.cgroup = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--userns")) {
            cfg.namespace_fds.user = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--userns2")) {
            cfg.namespace_fds.user2 = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--pidns")) {
            cfg.namespace_fds.pid = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--disable-userns")) {
            cfg.security.disable_userns = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--assert-userns-disabled")) {
            cfg.security.assert_userns_disabled = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--uid")) {
            cfg.runtime.uid = @intCast(try parseFd(try nextArg(raw, &i, arg)));
            continue;
        }
        if (std.mem.eql(u8, arg, "--gid")) {
            cfg.runtime.gid = @intCast(try parseFd(try nextArg(raw, &i, arg)));
            continue;
        }
        if (std.mem.eql(u8, arg, "--hostname")) {
            cfg.runtime.hostname = try nextArg(raw, &i, arg);
            continue;
        }

        if (std.mem.eql(u8, arg, "--argv0")) {
            cfg.process.argv0 = try nextArg(raw, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--chdir")) {
            cfg.process.chdir = try nextArg(raw, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--setenv")) {
            const key = try nextArg(raw, &i, arg);
            const value = try nextArg(raw, &i, arg);
            try env_set.append(allocator, .{ .key = key, .value = value });
            continue;
        }
        if (std.mem.eql(u8, arg, "--unsetenv")) {
            try env_unset.append(allocator, try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--clearenv")) {
            cfg.process.clear_env = true;
            continue;
        }

        if (std.mem.eql(u8, arg, "--lock-file")) {
            cfg.status.lock_file_path = try nextArg(raw, &i, arg);
            continue;
        }
        if (std.mem.eql(u8, arg, "--sync-fd")) {
            cfg.status.sync_fd = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--block-fd")) {
            cfg.status.block_fd = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--userns-block-fd")) {
            cfg.status.userns_block_fd = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--info-fd")) {
            cfg.status.info_fd = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--json-status-fd")) {
            cfg.status.json_status_fd = try parseFd(try nextArg(raw, &i, arg));
            continue;
        }

        if (std.mem.eql(u8, arg, "--perms")) {
            pending_mode = try std.fmt.parseInt(u32, try nextArg(raw, &i, arg), 8);
            continue;
        }
        if (std.mem.eql(u8, arg, "--size")) {
            pending_size = try std.fmt.parseInt(usize, try nextArg(raw, &i, arg), 10);
            continue;
        }

        if (std.mem.eql(u8, arg, "--bind")) {
            const src = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .bind = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--bind-try")) {
            const src = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .bind_try = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dev-bind")) {
            const src = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .dev_bind = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dev-bind-try")) {
            const src = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .dev_bind_try = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-bind")) {
            const src = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .ro_bind = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-bind-try")) {
            const src = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .ro_bind_try = .{ .src = src, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--remount-ro")) {
            try fs_actions.append(allocator, .{ .remount_ro = try nextArg(raw, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--proc")) {
            try fs_actions.append(allocator, .{ .proc = try nextArg(raw, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dev")) {
            try fs_actions.append(allocator, .{ .dev = try nextArg(raw, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--tmpfs")) {
            const dest = try nextArg(raw, &i, arg);
            try maybeApplyPending(allocator, &fs_actions, &pending_mode, &pending_size);
            try fs_actions.append(allocator, .{ .tmpfs = .{ .dest = dest, .mode = pending_mode, .size_bytes = pending_size } });
            pending_mode = null;
            pending_size = null;
            continue;
        }
        if (std.mem.eql(u8, arg, "--mqueue")) {
            try fs_actions.append(allocator, .{ .mqueue = try nextArg(raw, &i, arg) });
            continue;
        }
        if (std.mem.eql(u8, arg, "--dir")) {
            const dest = try nextArg(raw, &i, arg);
            try maybeApplyPending(allocator, &fs_actions, &pending_mode, &pending_size);
            try fs_actions.append(allocator, .{ .dir = .{ .path = dest, .mode = pending_mode } });
            pending_mode = null;
            pending_size = null;
            continue;
        }
        if (std.mem.eql(u8, arg, "--file")) {
            const fd = try parseFd(try nextArg(raw, &i, arg));
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .file_fd = .{ .path = dest, .fd = fd } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--bind-data")) {
            const fd = try parseFd(try nextArg(raw, &i, arg));
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .bind_data_fd = .{ .dest = dest, .fd = fd } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-bind-data")) {
            const fd = try parseFd(try nextArg(raw, &i, arg));
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .ro_bind_data_fd = .{ .dest = dest, .fd = fd } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--symlink")) {
            const src = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .symlink = .{ .target = src, .path = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--chmod")) {
            const mode = try std.fmt.parseInt(u32, try nextArg(raw, &i, arg), 8);
            const path = try nextArg(raw, &i, arg);
            try fs_actions.append(allocator, .{ .chmod = .{ .path = path, .mode = mode } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--overlay-src")) {
            const src = try nextArg(raw, &i, arg);
            const key = try std.fmt.allocPrint(allocator, "ov{d}", .{overlay_key_index});
            overlay_key_index += 1;
            latest_overlay_key = key;
            try fs_actions.append(allocator, .{ .overlay_src = .{ .key = key, .path = src } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--overlay")) {
            const upper = try nextArg(raw, &i, arg);
            const work = try nextArg(raw, &i, arg);
            const dest = try nextArg(raw, &i, arg);
            const key = latest_overlay_key orelse return error.MissingOverlaySource;
            try fs_actions.append(allocator, .{ .overlay = .{ .source_key = key, .upper = upper, .work = work, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--tmp-overlay")) {
            const dest = try nextArg(raw, &i, arg);
            const key = latest_overlay_key orelse return error.MissingOverlaySource;
            try fs_actions.append(allocator, .{ .tmp_overlay = .{ .source_key = key, .dest = dest } });
            continue;
        }
        if (std.mem.eql(u8, arg, "--ro-overlay")) {
            const dest = try nextArg(raw, &i, arg);
            const key = latest_overlay_key orelse return error.MissingOverlaySource;
            try fs_actions.append(allocator, .{ .ro_overlay = .{ .source_key = key, .dest = dest } });
            continue;
        }

        if (std.mem.eql(u8, arg, "--seccomp")) {
            const fd = try parseFd(try nextArg(raw, &i, arg));
            seccomp_fds.clearRetainingCapacity();
            try seccomp_fds.append(allocator, fd);
            continue;
        }
        if (std.mem.eql(u8, arg, "--add-seccomp-fd")) {
            const fd = try parseFd(try nextArg(raw, &i, arg));
            try seccomp_fds.append(allocator, fd);
            continue;
        }
        if (std.mem.eql(u8, arg, "--exec-label") or std.mem.eql(u8, arg, "--file-label")) {
            return error.UnsupportedOption;
        }
        if (std.mem.eql(u8, arg, "--new-session")) {
            cfg.process.new_session = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--die-with-parent")) {
            cfg.process.die_with_parent = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--as-pid-1")) {
            cfg.runtime.as_pid_1 = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--cap-add")) {
            try appendCapabilities(allocator, &cap_add, try nextArg(raw, &i, arg));
            continue;
        }
        if (std.mem.eql(u8, arg, "--cap-drop")) {
            try appendCapabilities(allocator, &cap_drop, try nextArg(raw, &i, arg));
            continue;
        }

        return error.UnknownOption;
    }

    cfg.process.set_env = try env_set.toOwnedSlice(allocator);
    cfg.process.unset_env = try env_unset.toOwnedSlice(allocator);
    cfg.security.cap_add = try cap_add.toOwnedSlice(allocator);
    cfg.security.cap_drop = try cap_drop.toOwnedSlice(allocator);
    cfg.security.seccomp_filter_fds = try seccomp_fds.toOwnedSlice(allocator);
    cfg.fs_actions = try fs_actions.toOwnedSlice(allocator);
    if (cfg.fs_actions.len > 0) cfg.isolation.mount = true;
    cfg.cmd = if (command.items.len == 0) &.{"/bin/sh"} else try command.toOwnedSlice(allocator);

    return .{ .cfg = cfg, .cmd = cfg.cmd };
}

fn appendCapabilities(allocator: std.mem.Allocator, out: *std.ArrayList(u8), raw: []const u8) !void {
    if (std.ascii.eqlIgnoreCase(raw, "ALL")) {
        var cap: u8 = 0;
        while (cap < 64) : (cap += 1) {
            if (std.os.linux.CAP.valid(cap)) {
                try out.append(allocator, cap);
            }
        }
        return;
    }

    try out.append(allocator, try parseCapability(raw));
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

fn maybeApplyPending(allocator: std.mem.Allocator, actions: *std.ArrayList(voidbox.FsAction), pending_mode: *?u32, pending_size: *?usize) !void {
    if (pending_mode.*) |mode| {
        try actions.append(allocator, .{ .perms = mode });
    }
    if (pending_size.*) |size| {
        try actions.append(allocator, .{ .size = size });
    }
}

fn nextArg(args: []const []const u8, i: *usize, option: []const u8) ![]const u8 {
    if (i.* + 1 >= args.len) {
        std.debug.print("missing value for {s}\n", .{option});
        return error.MissingOptionValue;
    }
    i.* += 1;
    return args[i.*];
}

fn parseFd(raw: []const u8) !i32 {
    const v = try std.fmt.parseInt(i32, raw, 10);
    if (v < 0) return error.InvalidFd;
    return v;
}

fn printCliError(err: anyerror) !void {
    switch (err) {
        error.HelpRequested => {},
        error.UnsupportedOption => std.debug.print("unsupported option in current voidbox backend\n", .{}),
        else => std.debug.print("argument error: {s}\n", .{@errorName(err)}),
    }
}

fn printUsage() !void {
    const out = std.fs.File.stderr().deprecatedWriter();
    try out.writeAll(
        "usage: vb [OPTION...] [--] COMMAND [ARG...]\n" ++
            "       vb doctor [--json] [--strict]\n" ++
            "\n" ++
            "bubblewrap-compatible options (implemented):\n" ++
            "  --unshare-{user,ipc,pid,net,uts,cgroup}, --unshare-all, --share-net\n" ++
            "  --userns FD --userns2 FD --pidns FD --uid UID --gid GID --hostname HOST\n" ++
            "  --chdir DIR --setenv VAR VALUE --unsetenv VAR --clearenv --argv0 VALUE\n" ++
            "  --sync-fd FD --lock-file PATH --block-fd FD --userns-block-fd FD\n" ++
            "  --info-fd FD --json-status-fd FD --new-session --die-with-parent --as-pid-1\n" ++
            "  --cap-add CAP --cap-drop CAP --seccomp FD --add-seccomp-fd FD\n" ++
            "  --perms OCTAL --size BYTES\n" ++
            "  --bind SRC DEST --bind-try SRC DEST --dev-bind SRC DEST --dev-bind-try SRC DEST\n" ++
            "  --ro-bind SRC DEST --ro-bind-try SRC DEST --remount-ro DEST\n" ++
            "  --proc DEST --dev DEST --tmpfs DEST --mqueue DEST --dir DEST\n" ++
            "  --file FD DEST --bind-data FD DEST --ro-bind-data FD DEST\n" ++
            "  --symlink SRC DEST --chmod OCTAL PATH\n" ++
            "  --overlay-src SRC --overlay RWSRC WORKDIR DEST --tmp-overlay DEST --ro-overlay DEST\n" ++
            "  --help --version\n\n",
    );
}
