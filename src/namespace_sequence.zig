const std = @import("std");
const linux = std.os.linux;
const checkErr = @import("utils.zig").checkErr;

const NamespaceFds = @import("config.zig").NamespaceFds;

pub fn attachInitial(namespace_fds: NamespaceFds) !void {
    if (namespace_fds.user) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWUSER);
    }
    if (namespace_fds.mount) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWNS);
    }
    if (namespace_fds.net) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWNET);
    }
    if (namespace_fds.uts) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWUTS);
    }
    if (namespace_fds.ipc) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWIPC);
    }
    if (namespace_fds.pid) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWPID);
    }
}

pub fn attachUserNs2(namespace_fds: NamespaceFds) !void {
    if (namespace_fds.user2) |fd| {
        try attachNamespaceFd(fd, linux.CLONE.NEWUSER);
    }
}

fn attachNamespaceFd(fd: i32, nstype: u32) !void {
    const res = linux.syscall2(.setns, @as(usize, @bitCast(@as(isize, fd))), nstype);
    try checkErr(res, error.SetNsFailed);
}
