const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;
const FsAction = @import("config.zig").FsAction;
const fs_actions = @import("fs_actions.zig");

rootfs: []const u8,
actions: []const FsAction,

const Fs = @This();

pub fn init(rootfs: []const u8, actions: []const FsAction) Fs {
    return .{ .rootfs = rootfs, .actions = actions };
}

pub fn setup(self: *Fs, mount_fs: bool) !void {
    try checkErr(linux.chroot(@ptrCast(self.rootfs)), error.Chroot);
    try checkErr(linux.chdir("/"), error.Chdir);

    if (!mount_fs) return;

    if (self.actions.len == 0) {
        try setupDefaultMounts();
        return;
    }

    try fs_actions.execute(self.actions);
}

fn setupDefaultMounts() !void {
    try checkErr(linux.mount("proc", "proc", "proc", 0, 0), error.MountProc);
    try checkErr(linux.mount("tmpfs", "tmp", "tmpfs", 0, 0), error.MountTmpFs);
    _ = linux.mount("sysfs", "sys", "sysfs", 0, 0);
}
