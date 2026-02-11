const LinkMessage = @import("link.zig");
const RtNetLink = @import("../rtnetlink.zig");
const std = @import("std");
const log = std.log;
const nalign = @import("../utils.zig").nalign;
const linux = std.os.linux;

const LinkGet = @This();
pub const Options = struct {
    name: ?[]const u8 = null,
    index: ?u32 = null,
};

msg: LinkMessage,
nl: *RtNetLink,
opts: Options,
allocator: std.mem.Allocator,
pub fn init(allocator: std.mem.Allocator, nl: *RtNetLink, options: Options) LinkGet {
    const msg = LinkMessage.init(allocator, .get);
    return .{
        .msg = msg,
        .nl = nl,
        .opts = options,
        .allocator = allocator,
    };
}

fn name(self: *LinkGet, value: []const u8) !void {
    try self.msg.addAttr(.{ .name = value });
}

fn applyOptions(self: *LinkGet) !void {
    if (self.opts.name) |val| {
        try self.name(val);
    }
    if (self.opts.index) |val| {
        self.msg.msg.header.index = @intCast(val);
    }
}

pub fn exec(self: *LinkGet) !LinkMessage {
    try self.applyOptions();

    const data = try self.msg.compose();
    defer self.msg.allocator.free(data);

    try self.nl.send(data);
    return self.recv();
}

fn recv(self: *LinkGet) !LinkMessage {
    var buff: [512]u8 = undefined;
    const n = try self.nl.recv(&buff);
    if (n < @sizeOf(linux.nlmsghdr)) return error.InvalidResponse;

    var start: usize = 0;
    var link_info = LinkMessage.init(self.nl.allocator, .create); // req_type doesn't matter here
    errdefer link_info.deinit();

    const header = std.mem.bytesAsValue(linux.nlmsghdr, buff[0..@sizeOf(linux.nlmsghdr)]);
    if (header.type == .ERROR) {
        if (n < @sizeOf(RtNetLink.NlMsgError)) return error.InvalidResponse;
        const response = std.mem.bytesAsValue(RtNetLink.NlMsgError, buff[0..]);
        try RtNetLink.handle_ack(response.*);
        unreachable;
    }
    if (header.len < @sizeOf(linux.nlmsghdr) + @sizeOf(linux.ifinfomsg) or header.len > n) {
        return error.InvalidResponse;
    }

    start += @sizeOf(linux.nlmsghdr);
    link_info.hdr = header.*;

    log.info("header: {}", .{header});
    const ifinfo = std.mem.bytesAsValue(linux.ifinfomsg, buff[start .. start + @sizeOf(linux.ifinfomsg)]);
    start += @sizeOf(linux.ifinfomsg);
    link_info.msg.header = ifinfo.*;

    log.info("ifinfo: {}", .{ifinfo});
    while (start + @sizeOf(linux.rtattr) <= header.len) {
        const rtattr = std.mem.bytesAsValue(linux.rtattr, buff[start .. start + @sizeOf(linux.rtattr)]);
        if (rtattr.len < @sizeOf(linux.rtattr)) return error.InvalidResponse;
        if (start + rtattr.len > header.len) return error.InvalidResponse;
        switch (rtattr.type.link) {
            .IFNAME => {
                if (rtattr.len == @sizeOf(linux.rtattr)) {
                    start += nalign(rtattr.len);
                    continue;
                }
                const value = buff[start + @sizeOf(linux.rtattr) .. start + rtattr.len - 1]; // skip null terminating byte
                const ifname = try self.allocator.alloc(u8, value.len);
                @memcpy(ifname, value);
                log.info("name: {s}", .{ifname});
                try link_info.addAttr(.{ .name = ifname });
            },
            else => {},
        }
        start += nalign(rtattr.len);
    }

    // TODO: handle multipart messages
    // parse ACK/NACK response
    try self.nl.recv_ack();
    return link_info;
}
