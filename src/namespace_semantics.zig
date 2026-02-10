const config = @import("config.zig");

const IsolationOptions = config.IsolationOptions;
const NamespaceFds = config.NamespaceFds;
const SecurityOptions = config.SecurityOptions;
const JailConfig = config.JailConfig;

pub fn validate(isolation: IsolationOptions, namespace_fds: NamespaceFds, security: SecurityOptions) !void {
    if (namespace_fds.net != null and isolation.net) return error.NamespaceAttachConflict;
    if (namespace_fds.mount != null and isolation.mount) return error.NamespaceAttachConflict;
    if (namespace_fds.uts != null and isolation.uts) return error.NamespaceAttachConflict;
    if (namespace_fds.ipc != null and isolation.ipc) return error.NamespaceAttachConflict;
    if (namespace_fds.pid != null and isolation.pid) return error.NamespaceAttachConflict;
    if (namespace_fds.user != null and isolation.user) return error.NamespaceAttachConflict;

    if (security.assert_userns_disabled and (isolation.user or namespace_fds.user != null)) {
        return error.AssertUserNsDisabledConflict;
    }

    if (security.disable_userns and namespace_fds.user != null) {
        return error.DisableUserNsConflict;
    }
}

pub fn normalized(jail_config: JailConfig) JailConfig {
    var out = jail_config;
    if (out.security.disable_userns) {
        out.isolation.user = false;
    }
    return out;
}

test "normalized disables user unshare when requested" {
    var cfg: JailConfig = .{
        .name = "x",
        .rootfs_path = "/",
        .cmd = &.{"/bin/sh"},
    };
    cfg.security.disable_userns = true;

    const out = normalized(cfg);
    try @import("std").testing.expect(!out.isolation.user);
}

test "validate rejects disable_userns with attached userns" {
    const cfg: JailConfig = .{
        .name = "x",
        .rootfs_path = "/",
        .cmd = &.{"/bin/sh"},
        .isolation = .{ .user = false },
        .namespace_fds = .{ .user = 3 },
        .security = .{ .disable_userns = true },
    };

    try @import("std").testing.expectError(error.DisableUserNsConflict, validate(cfg.isolation, cfg.namespace_fds, cfg.security));
}
