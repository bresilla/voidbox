const std = @import("std");
const log = std.log;
const linux = std.os.linux;
const Container = @import("container.zig");
const args = @import("args.zig");
const ps = @import("ps.zig");
const utils = @import("utils.zig");

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena_allocator.allocator();
    const cmd = try args.parseArgs(allocator);

    switch (cmd) {
        .run => |r| {
            try zspaceInit();
            var container = try Container.init(r, allocator);
            defer container.deinit();
            try container.run();
        },
        .help => {
            const stdout = std.fs.File.stdout().deprecatedWriter();
            _ = try stdout.write(args.help);
        },
        .ps => {
            const containers = try ps.runningContainers(allocator);
            var stdout = std.fs.File.stdout().deprecatedWriter();
            _ = try stdout.print("Running Containers:\n", .{});
            for (containers) |c| {
                try c.print(stdout);
            }
        },
    }
}

pub fn zspaceInit() !void {
    _ = try utils.createDirIfNotExists("/var/run/zspace");
    _ = try utils.createDirIfNotExists("/var/run/zspace/containers");
    _ = try utils.createDirIfNotExists("/var/run/zspace/containers/netns");
    const path = utils.CGROUP_PATH ++ "zspace/";
    if (!try utils.createDirIfNotExists(path)) return;

    // setup root cgroup
    const root_cgroup = path ++ "cgroup.subtree_control";
    var root_cgroup_file = try std.fs.openFileAbsolute(root_cgroup, .{ .mode = .write_only });
    defer root_cgroup_file.close();
    _ = try root_cgroup_file.write("+cpu +memory +pids"); // enable cpu, mem, and pid controllers in the root cgroup

}
