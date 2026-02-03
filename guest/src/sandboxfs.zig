const std = @import("std");
const cbor = @import("sandboxd").cbor;
const fs_rpc = @import("sandboxd").fs_rpc;
const log = std.log.scoped(.sandboxfs);

const FUSE_ROOT_ID: u64 = 1;
const MAX_RPC_DATA = 60 * 1024;

const FuseOp = struct {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const SETATTR: u32 = 4;
    pub const MKDIR: u32 = 9;
    pub const UNLINK: u32 = 10;
    pub const RENAME: u32 = 12;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const WRITE: u32 = 16;
    pub const RELEASE: u32 = 18;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
    pub const CREATE: u32 = 35;
};

const FuseAttr = extern struct {
    ino: u64,
    size: u64,
    blocks: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    nlink: u32,
    uid: u32,
    gid: u32,
    rdev: u32,
    blksize: u32,
    padding: u32,
};

const FuseEntryOut = extern struct {
    nodeid: u64,
    generation: u64,
    entry_valid: u64,
    attr_valid: u64,
    entry_valid_nsec: u32,
    attr_valid_nsec: u32,
    attr: FuseAttr,
};

const FuseAttrOut = extern struct {
    attr_valid: u64,
    attr_valid_nsec: u32,
    dummy: u32,
    attr: FuseAttr,
};

const FuseOpenOut = extern struct {
    fh: u64,
    open_flags: u32,
    padding: u32,
};

const FuseWriteOut = extern struct {
    size: u32,
    padding: u32,
};

const FuseOutHeader = extern struct {
    len: u32,
    @"error": i32,
    unique: u64,
};

const FuseDirent = extern struct {
    ino: u64,
    off: u64,
    namelen: u32,
    type: u32,
};

const FuseInHeader = struct {
    len: u32,
    opcode: u32,
    unique: u64,
    nodeid: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    padding: u32,
};

const FuseInitIn = struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
};

const FuseInitOut = extern struct {
    major: u32,
    minor: u32,
    max_readahead: u32,
    flags: u32,
    max_background: u16,
    congestion_threshold: u16,
    max_write: u32,
    time_gran: u32,
    max_pages: u16,
    map_alignment: u16,
    flags2: u32,
    unused: [7]u32,
};

const FuseOpenIn = struct {
    flags: u32,
};

const FuseReadIn = struct {
    fh: u64,
    offset: u64,
    size: u32,
};

const FuseWriteIn = struct {
    fh: u64,
    offset: u64,
    size: u32,
};

const FuseCreateIn = struct {
    flags: u32,
    mode: u32,
    umask: u32,
};

const FuseMkdirIn = struct {
    mode: u32,
    umask: u32,
};

const FuseRenameIn = struct {
    newdir: u64,
    flags: u32,
};

const FuseSetattrIn = struct {
    valid: u32,
    padding: u32,
    fh: u64,
    size: u64,
    lock_owner: u64,
    atime: u64,
    mtime: u64,
    ctime: u64,
    atimensec: u32,
    mtimensec: u32,
    ctimensec: u32,
    mode: u32,
    unused4: u32,
    uid: u32,
    gid: u32,
    unused5: u32,
};

const FuseReleaseIn = struct {
    fh: u64,
    flags: u32,
    release_flags: u32,
    lock_owner: u64,
};

const FattrFlags = struct {
    pub const SIZE: u32 = 1 << 3;
};

const DefaultTtls = struct {
    pub const attr_ms: u64 = 1000;
    pub const entry_ms: u64 = 1000;
};

const LruCache = struct {
    const EntryValue = struct {
        attr: FuseAttr,
        kind: u32,
    };

    const Node = struct {
        key: u64,
        value: EntryValue,
        link: std.DoublyLinkedList.Node = .{},
    };

    allocator: std.mem.Allocator,
    max_entries: usize,
    list: std.DoublyLinkedList = .{},
    map: std.AutoHashMap(u64, *Node),

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) LruCache {
        return .{ .allocator = allocator, .max_entries = max_entries, .map = std.AutoHashMap(u64, *Node).init(allocator) };
    }

    pub fn deinit(self: *LruCache) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    pub fn put(self: *LruCache, key: u64, value: EntryValue) !void {
        if (self.map.get(key)) |node| {
            node.value = value;
            self.touch(node);
            return;
        }

        const node = try self.allocator.create(Node);
        node.* = .{ .key = key, .value = value, .link = .{} };
        self.list.prepend(&node.link);
        try self.map.put(key, node);
        try self.evictIfNeeded();
    }

    pub fn get(self: *LruCache, key: u64) ?EntryValue {
        if (self.map.get(key)) |node| {
            self.touch(node);
            return node.value;
        }
        return null;
    }

    pub fn remove(self: *LruCache, key: u64) void {
        if (self.map.fetchRemove(key)) |entry| {
            self.list.remove(&entry.value.link);
            self.allocator.destroy(entry.value);
        }
    }

    fn touch(self: *LruCache, node: *Node) void {
        self.list.remove(&node.link);
        self.list.prepend(&node.link);
    }

    fn evictIfNeeded(self: *LruCache) !void {
        while (self.map.count() > self.max_entries) {
            const tail_link = self.list.pop() orelse return;
            const tail: *Node = @fieldParentPtr("link", tail_link);
            _ = self.map.remove(tail.key);
            self.allocator.destroy(tail);
        }
    }
};

const HandleCache = struct {
    const Node = struct {
        key: u64,
        value: u64,
        link: std.DoublyLinkedList.Node = .{},
    };

    allocator: std.mem.Allocator,
    max_entries: usize,
    list: std.DoublyLinkedList = .{},
    map: std.AutoHashMap(u64, *Node),

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) HandleCache {
        return .{ .allocator = allocator, .max_entries = max_entries, .map = std.AutoHashMap(u64, *Node).init(allocator) };
    }

    pub fn deinit(self: *HandleCache) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.map.deinit();
    }

    pub fn put(self: *HandleCache, key: u64, value: u64) !void {
        if (self.map.get(key)) |node| {
            node.value = value;
            self.touch(node);
            return;
        }

        const node = try self.allocator.create(Node);
        node.* = .{ .key = key, .value = value, .link = .{} };
        self.list.prepend(&node.link);
        try self.map.put(key, node);
        try self.evictIfNeeded();
    }

    pub fn get(self: *HandleCache, key: u64) ?u64 {
        if (self.map.get(key)) |node| {
            self.touch(node);
            return node.value;
        }
        return null;
    }

    pub fn remove(self: *HandleCache, key: u64) void {
        if (self.map.fetchRemove(key)) |entry| {
            self.list.remove(&entry.value.link);
            self.allocator.destroy(entry.value);
        }
    }

    fn touch(self: *HandleCache, node: *Node) void {
        self.list.remove(&node.link);
        self.list.prepend(&node.link);
    }

    fn evictIfNeeded(self: *HandleCache) !void {
        while (self.map.count() > self.max_entries) {
            const tail_link = self.list.pop() orelse return;
            const tail: *Node = @fieldParentPtr("link", tail_link);
            _ = self.map.remove(tail.key);
            self.allocator.destroy(tail);
        }
    }
};

const SandboxFs = struct {
    allocator: std.mem.Allocator,
    fuse_fd: std.posix.fd_t,
    rpc: ?fs_rpc.FsRpcClient,
    inode_cache: LruCache,
    handle_cache: HandleCache,

    pub fn init(allocator: std.mem.Allocator, fuse_fd: std.posix.fd_t, rpc: ?fs_rpc.FsRpcClient) SandboxFs {
        return .{
            .allocator = allocator,
            .fuse_fd = fuse_fd,
            .rpc = rpc,
            .inode_cache = LruCache.init(allocator, 512),
            .handle_cache = HandleCache.init(allocator, 512),
        };
    }

    pub fn deinit(self: *SandboxFs) void {
        self.inode_cache.deinit();
        self.handle_cache.deinit();
    }

    pub fn run(self: *SandboxFs) !void {
        var buffer: [128 * 1024]u8 = undefined;
        while (true) {
            const request = try readFuseRequest(self.fuse_fd, buffer[0..]);
            const header = try parseInHeader(request);
            const payload = request[@sizeOf(FuseInHeader)..];
            try self.handleRequest(header, payload);
        }
    }

    fn handleRequest(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        switch (header.opcode) {
            FuseOp.INIT => try self.handleInit(header, payload),
            FuseOp.LOOKUP => try self.handleLookup(header, payload),
            FuseOp.GETATTR => try self.handleGetattr(header),
            FuseOp.SETATTR => try self.handleSetattr(header, payload),
            FuseOp.MKDIR => try self.handleMkdir(header, payload),
            FuseOp.UNLINK => try self.handleUnlink(header, payload),
            FuseOp.RENAME => try self.handleRename(header, payload),
            FuseOp.OPEN => try self.handleOpen(header, payload),
            FuseOp.OPENDIR => try self.handleOpendir(header),
            FuseOp.READDIR => try self.handleReaddir(header, payload),
            FuseOp.RELEASEDIR => try self.handleReleaseDir(header),
            FuseOp.READ => try self.handleRead(header, payload),
            FuseOp.WRITE => try self.handleWrite(header, payload),
            FuseOp.CREATE => try self.handleCreate(header, payload),
            FuseOp.RELEASE => try self.handleRelease(header, payload),
            FuseOp.FORGET => return,
            else => try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS),
        }
    }

    fn handleInit(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        const init_in = try parseFuseInit(payload);
        const flags = init_in.flags;
        _ = flags;

        const out = FuseInitOut{
            .major = 7,
            .minor = 31,
            .max_readahead = init_in.max_readahead,
            .flags = (1 << 5),
            .max_background = 0,
            .congestion_threshold = 0,
            .max_write = MAX_RPC_DATA,
            .time_gran = 1,
            .max_pages = 0,
            .map_alignment = 0,
            .flags2 = 0,
            .unused = .{0} ** 7,
        };

        try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&out));
    }

    fn handleLookup(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        const name = parseName(payload);
        if (self.rpc) |*rpc| {
            var fields = [_]fs_rpc.Field{
                .{ .name = "parent_ino", .value = .{ .UInt = header.nodeid } },
                .{ .name = "name", .value = .{ .Text = name } },
            };
            var response = try rpc.request("lookup", &fields);
            defer response.deinit();

            if (response.err != 0) {
                try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
                return;
            }

            const res_map = response.res orelse return error.InvalidResponse;
            const entry_val = cbor.getMapValue(res_map, "entry") orelse return error.InvalidResponse;
            const entry_map = try expectMap(entry_val);
            const entry = try parseEntry(entry_map, DefaultTtls.attr_ms, DefaultTtls.entry_ms);

            try self.inode_cache.put(entry.attr.ino, .{ .attr = entry.attr, .kind = entry.attr.mode & 0xf000 });

            try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&entry.out));
            return;
        }

        if (header.nodeid == FUSE_ROOT_ID and std.mem.eql(u8, name, "data")) {
            const root = defaultDirAttr(FUSE_ROOT_ID + 1);
            const entry = buildEntry(root, DefaultTtls.attr_ms, DefaultTtls.entry_ms);
            try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&entry));
            return;
        }

        try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOENT);
    }

    fn handleGetattr(self: *SandboxFs, header: FuseInHeader) !void {
        if (self.rpc) |*rpc| {
            var fields = [_]fs_rpc.Field{.{ .name = "ino", .value = .{ .UInt = header.nodeid } }};
            var response = try rpc.request("getattr", &fields);
            defer response.deinit();

            if (response.err != 0) {
                try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
                return;
            }

            const res_map = response.res orelse return error.InvalidResponse;
            const attr_val = cbor.getMapValue(res_map, "attr") orelse return error.InvalidResponse;
            const attr_map = try expectMap(attr_val);
            const attr = try parseAttr(attr_map, header.nodeid);
            const attr_ttl_ms = getMapU64(res_map, "attr_ttl_ms") orelse DefaultTtls.attr_ms;

            try self.inode_cache.put(attr.ino, .{ .attr = attr, .kind = attr.mode & 0xf000 });

            const out = buildAttrOut(attr, attr_ttl_ms);
            try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&out));
            return;
        }

        const attr = defaultDirAttr(header.nodeid);
        const out = buildAttrOut(attr, DefaultTtls.attr_ms);
        try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&out));
    }

    fn handleSetattr(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const setattr = try parseSetattr(payload);
        if ((setattr.valid & FattrFlags.SIZE) == 0) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        var fields = [_]fs_rpc.Field{
            .{ .name = "ino", .value = .{ .UInt = header.nodeid } },
            .{ .name = "size", .value = .{ .UInt = setattr.size } },
        };
        var response = try self.rpc.?.request("truncate", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        try sendResponse(self.fuse_fd, header.unique, 0, &.{});
    }

    fn handleMkdir(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const mkdir = try parseMkdir(payload);
        const name = parseName(payload[@sizeOf(FuseMkdirIn)..]);

        var fields = [_]fs_rpc.Field{
            .{ .name = "parent_ino", .value = .{ .UInt = header.nodeid } },
            .{ .name = "name", .value = .{ .Text = name } },
            .{ .name = "mode", .value = .{ .UInt = mkdir.mode } },
        };
        var response = try self.rpc.?.request("mkdir", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        const res_map = response.res orelse return error.InvalidResponse;
        const entry_val = cbor.getMapValue(res_map, "entry") orelse return error.InvalidResponse;
        const entry_map = try expectMap(entry_val);
        const entry = try parseEntry(entry_map, DefaultTtls.attr_ms, DefaultTtls.entry_ms);

        try self.inode_cache.put(entry.attr.ino, .{ .attr = entry.attr, .kind = entry.attr.mode & 0xf000 });

        try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&entry.out));
    }

    fn handleUnlink(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const name = parseName(payload);
        var fields = [_]fs_rpc.Field{
            .{ .name = "parent_ino", .value = .{ .UInt = header.nodeid } },
            .{ .name = "name", .value = .{ .Text = name } },
        };
        var response = try self.rpc.?.request("unlink", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        try sendResponse(self.fuse_fd, header.unique, 0, &.{});
    }

    fn handleRename(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const rename = try parseRename(payload);
        const names = payload[@sizeOf(FuseRenameIn)..];
        const old_name = parseName(names);
        const rest = names[old_name.len + 1 ..];
        const new_name = parseName(rest);

        var fields = [_]fs_rpc.Field{
            .{ .name = "old_parent_ino", .value = .{ .UInt = header.nodeid } },
            .{ .name = "old_name", .value = .{ .Text = old_name } },
            .{ .name = "new_parent_ino", .value = .{ .UInt = rename.newdir } },
            .{ .name = "new_name", .value = .{ .Text = new_name } },
            .{ .name = "flags", .value = .{ .UInt = rename.flags } },
        };
        var response = try self.rpc.?.request("rename", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        try sendResponse(self.fuse_fd, header.unique, 0, &.{});
    }

    fn handleOpen(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const open = try parseOpen(payload);
        var fields = [_]fs_rpc.Field{
            .{ .name = "ino", .value = .{ .UInt = header.nodeid } },
            .{ .name = "flags", .value = .{ .UInt = open.flags } },
        };
        var response = try self.rpc.?.request("open", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        const res_map = response.res orelse return error.InvalidResponse;
        const fh = getMapU64(res_map, "fh") orelse return error.InvalidResponse;
        const open_flags = getMapU32(res_map, "open_flags") orelse 0;
        try self.handle_cache.put(fh, header.nodeid);

        const out = FuseOpenOut{ .fh = fh, .open_flags = open_flags, .padding = 0 };
        try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&out));
    }

    fn handleOpendir(self: *SandboxFs, header: FuseInHeader) !void {
        const out = FuseOpenOut{ .fh = header.nodeid, .open_flags = 0, .padding = 0 };
        try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&out));
    }

    fn handleReaddir(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const read_in = try parseRead(payload);
        const max_entries = @max(@as(u32, 1), read_in.size / 256);

        var fields = [_]fs_rpc.Field{
            .{ .name = "ino", .value = .{ .UInt = header.nodeid } },
            .{ .name = "offset", .value = .{ .UInt = read_in.offset } },
            .{ .name = "max_entries", .value = .{ .UInt = max_entries } },
        };
        var response = try self.rpc.?.request("readdir", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        const res_map = response.res orelse return error.InvalidResponse;
        const entries_val = cbor.getMapValue(res_map, "entries") orelse return error.InvalidResponse;
        const entries = try expectArray(entries_val);

        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(self.allocator);

        for (entries) |entry_val| {
            const entry_map = try expectMap(entry_val);
            const ino = getMapU64(entry_map, "ino") orelse return error.InvalidResponse;
            const name_val = cbor.getMapValue(entry_map, "name") orelse return error.InvalidResponse;
            const name = try expectText(name_val);
            const entry_type = getMapU32(entry_map, "type") orelse 0;
            const offset = getMapU64(entry_map, "offset") orelse 0;

            const dirent = FuseDirent{
                .ino = ino,
                .off = offset,
                .namelen = @intCast(name.len),
                .type = entry_type,
            };

            const start_len = buf.items.len;
            try buf.appendSlice(self.allocator, std.mem.asBytes(&dirent));
            try buf.appendSlice(self.allocator, name);

            const padded_len = alignDirent(buf.items.len - start_len);
            const padding = padded_len - (buf.items.len - start_len);
            if (padding > 0) {
                try buf.appendNTimes(self.allocator, 0, padding);
            }

            if (buf.items.len >= @as(usize, @intCast(read_in.size))) {
                break;
            }
        }

        try sendResponse(self.fuse_fd, header.unique, 0, buf.items);
    }

    fn handleReleaseDir(self: *SandboxFs, header: FuseInHeader) !void {
        try sendResponse(self.fuse_fd, header.unique, 0, &.{});
    }

    fn handleRead(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const read_in = try parseRead(payload);
        const size = @min(read_in.size, @as(u32, MAX_RPC_DATA));

        var fields = [_]fs_rpc.Field{
            .{ .name = "fh", .value = .{ .UInt = read_in.fh } },
            .{ .name = "offset", .value = .{ .UInt = read_in.offset } },
            .{ .name = "size", .value = .{ .UInt = size } },
        };
        var response = try self.rpc.?.request("read", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        const res_map = response.res orelse return error.InvalidResponse;
        const data_val = cbor.getMapValue(res_map, "data") orelse return error.InvalidResponse;
        const data = try expectBytes(data_val);

        try sendResponse(self.fuse_fd, header.unique, 0, data);
    }

    fn handleWrite(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const write_in = try parseWrite(payload);
        const data_offset = @sizeOf(FuseWriteIn);
        if (payload.len < data_offset) return error.InvalidRequest;
        const data = payload[data_offset..];
        const size = @min(@min(write_in.size, @as(u32, @intCast(data.len))), @as(u32, MAX_RPC_DATA));
        const clipped = data[0..@intCast(size)];

        var fields = [_]fs_rpc.Field{
            .{ .name = "fh", .value = .{ .UInt = write_in.fh } },
            .{ .name = "offset", .value = .{ .UInt = write_in.offset } },
            .{ .name = "data", .value = .{ .Bytes = clipped } },
        };
        var response = try self.rpc.?.request("write", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        const res_map = response.res orelse return error.InvalidResponse;
        const written = getMapU32(res_map, "size") orelse size;
        const out = FuseWriteOut{ .size = written, .padding = 0 };
        try sendResponse(self.fuse_fd, header.unique, 0, std.mem.asBytes(&out));
    }

    fn handleCreate(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const create = try parseCreate(payload);
        const name = parseName(payload[@sizeOf(FuseCreateIn)..]);

        var fields = [_]fs_rpc.Field{
            .{ .name = "parent_ino", .value = .{ .UInt = header.nodeid } },
            .{ .name = "name", .value = .{ .Text = name } },
            .{ .name = "mode", .value = .{ .UInt = create.mode } },
            .{ .name = "flags", .value = .{ .UInt = create.flags } },
        };
        var response = try self.rpc.?.request("create", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        const res_map = response.res orelse return error.InvalidResponse;
        const entry_val = cbor.getMapValue(res_map, "entry") orelse return error.InvalidResponse;
        const entry_map = try expectMap(entry_val);
        const entry = try parseEntry(entry_map, DefaultTtls.attr_ms, DefaultTtls.entry_ms);
        const fh = getMapU64(res_map, "fh") orelse return error.InvalidResponse;
        const open_flags = getMapU32(res_map, "open_flags") orelse 0;
        try self.handle_cache.put(fh, entry.attr.ino);

        var buf = std.ArrayList(u8).empty;
        defer buf.deinit(self.allocator);
        try buf.appendSlice(self.allocator, std.mem.asBytes(&entry.out));
        const open_out = FuseOpenOut{ .fh = fh, .open_flags = open_flags, .padding = 0 };
        try buf.appendSlice(self.allocator, std.mem.asBytes(&open_out));

        try sendResponse(self.fuse_fd, header.unique, 0, buf.items);
    }

    fn handleRelease(self: *SandboxFs, header: FuseInHeader, payload: []const u8) !void {
        if (self.rpc == null) {
            try sendError(self.fuse_fd, header.unique, std.os.linux.E.NOSYS);
            return;
        }

        const release = try parseRelease(payload);
        var fields = [_]fs_rpc.Field{.{ .name = "fh", .value = .{ .UInt = release.fh } }};
        var response = try self.rpc.?.request("release", &fields);
        defer response.deinit();

        if (response.err != 0) {
            try sendError(self.fuse_fd, header.unique, errnoFromResponse(response.err));
            return;
        }

        self.handle_cache.remove(release.fh);
        try sendResponse(self.fuse_fd, header.unique, 0, &.{});
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var mount_point: []const u8 = "/data";
    var rpc_path: []const u8 = "/dev/vport0p2";

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--mount") and i + 1 < args.len) {
            mount_point = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, args[i], "--rpc-path") and i + 1 < args.len) {
            rpc_path = args[i + 1];
            i += 1;
            continue;
        }
    }

    const fuse_fd = try std.posix.open("/dev/fuse", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    defer std.posix.close(fuse_fd);

    const rpc_fd = openRpcPort(rpc_path);
    var rpc_client: ?fs_rpc.FsRpcClient = null;
    if (rpc_fd) |fd| {
        rpc_client = fs_rpc.FsRpcClient.init(allocator, fd);
        log.info("connected rpc at {s}", .{rpc_path});
    } else {
        log.warn("rpc port {s} unavailable; running in stub mode", .{rpc_path});
    }

    try mountFuse(allocator, fuse_fd, mount_point);
    log.info("mounted sandboxfs at {s}", .{mount_point});

    var sandboxfs = SandboxFs.init(allocator, fuse_fd, rpc_client);
    defer sandboxfs.deinit();

    try sandboxfs.run();
}

fn mountFuse(allocator: std.mem.Allocator, fuse_fd: std.posix.fd_t, mount_point: []const u8) !void {
    const data = try std.fmt.allocPrint(allocator, "fd={d},rootmode=40000,user_id=0,group_id=0,default_permissions", .{fuse_fd});
    defer allocator.free(data);
    const data_z = try makeZ(allocator, data);
    defer allocator.free(data_z);
    const mount_z = try makeZ(allocator, mount_point);
    defer allocator.free(mount_z);
    const source_z = try makeZ(allocator, "sandboxfs");
    defer allocator.free(source_z);
    const fstype_z = try makeZ(allocator, "fuse.sandboxfs");
    defer allocator.free(fstype_z);

    const rc = std.os.linux.mount(source_z.ptr, mount_z.ptr, fstype_z.ptr, std.os.linux.MS.NOSUID | std.os.linux.MS.NODEV, @intFromPtr(data_z.ptr));
    const err = std.os.linux.E.init(rc);
    if (err != .SUCCESS) {
        log.err("mount failed: {s}", .{@tagName(err)});
        return error.MountFailed;
    }
}

fn makeZ(allocator: std.mem.Allocator, text: []const u8) ![:0]u8 {
    const buf = try allocator.alloc(u8, text.len + 1);
    @memcpy(buf[0..text.len], text);
    buf[text.len] = 0;
    return buf[0..text.len :0];
}

fn openRpcPort(path: []const u8) ?std.posix.fd_t {
    return std.posix.open(path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0) catch null;
}

fn readFuseRequest(fd: std.posix.fd_t, buffer: []u8) ![]u8 {
    var total: usize = 0;
    var expected: ?usize = null;
    while (true) {
        if (total >= buffer.len) return error.BufferTooSmall;
        const n = try std.posix.read(fd, buffer[total..]);
        if (n == 0) return error.EndOfStream;
        total += n;
        if (expected == null and total >= 4) {
            const len = readIntLittle(u32, buffer[0..4]);
            expected = len;
        }
        if (expected) |len| {
            if (total >= len) return buffer[0..len];
        }
    }
}

fn parseInHeader(request: []const u8) !FuseInHeader {
    if (request.len < @sizeOf(FuseInHeader)) return error.InvalidRequest;
    var offset: usize = 0;
    const len = try readU32(request, &offset);
    const opcode = try readU32(request, &offset);
    const unique = try readU64(request, &offset);
    const nodeid = try readU64(request, &offset);
    const uid = try readU32(request, &offset);
    const gid = try readU32(request, &offset);
    const pid = try readU32(request, &offset);
    const padding = try readU32(request, &offset);
    return .{
        .len = len,
        .opcode = opcode,
        .unique = unique,
        .nodeid = nodeid,
        .uid = uid,
        .gid = gid,
        .pid = pid,
        .padding = padding,
    };
}

fn parseFuseInit(payload: []const u8) !FuseInitIn {
    var offset: usize = 0;
    const major = try readU32(payload, &offset);
    const minor = try readU32(payload, &offset);
    const max_readahead = try readU32(payload, &offset);
    const flags = try readU32(payload, &offset);
    return .{ .major = major, .minor = minor, .max_readahead = max_readahead, .flags = flags };
}

fn parseOpen(payload: []const u8) !FuseOpenIn {
    var offset: usize = 0;
    return .{ .flags = try readU32(payload, &offset) };
}

fn parseRead(payload: []const u8) !FuseReadIn {
    var offset: usize = 0;
    const fh = try readU64(payload, &offset);
    const off = try readU64(payload, &offset);
    const size = try readU32(payload, &offset);
    return .{ .fh = fh, .offset = off, .size = size };
}

fn parseWrite(payload: []const u8) !FuseWriteIn {
    var offset: usize = 0;
    const fh = try readU64(payload, &offset);
    const off = try readU64(payload, &offset);
    const size = try readU32(payload, &offset);
    return .{ .fh = fh, .offset = off, .size = size };
}

fn parseCreate(payload: []const u8) !FuseCreateIn {
    var offset: usize = 0;
    const flags = try readU32(payload, &offset);
    const mode = try readU32(payload, &offset);
    const umask = try readU32(payload, &offset);
    return .{ .flags = flags, .mode = mode, .umask = umask };
}

fn parseMkdir(payload: []const u8) !FuseMkdirIn {
    var offset: usize = 0;
    const mode = try readU32(payload, &offset);
    const umask = try readU32(payload, &offset);
    return .{ .mode = mode, .umask = umask };
}

fn parseRename(payload: []const u8) !FuseRenameIn {
    var offset: usize = 0;
    const newdir = try readU64(payload, &offset);
    const flags = try readU32(payload, &offset);
    return .{ .newdir = newdir, .flags = flags };
}

fn parseSetattr(payload: []const u8) !FuseSetattrIn {
    var offset: usize = 0;
    const valid = try readU32(payload, &offset);
    const padding = try readU32(payload, &offset);
    const fh = try readU64(payload, &offset);
    const size = try readU64(payload, &offset);
    const lock_owner = try readU64(payload, &offset);
    const atime = try readU64(payload, &offset);
    const mtime = try readU64(payload, &offset);
    const ctime = try readU64(payload, &offset);
    const atimensec = try readU32(payload, &offset);
    const mtimensec = try readU32(payload, &offset);
    const ctimensec = try readU32(payload, &offset);
    const mode = try readU32(payload, &offset);
    const unused4 = try readU32(payload, &offset);
    const uid = try readU32(payload, &offset);
    const gid = try readU32(payload, &offset);
    const unused5 = try readU32(payload, &offset);
    return .{
        .valid = valid,
        .padding = padding,
        .fh = fh,
        .size = size,
        .lock_owner = lock_owner,
        .atime = atime,
        .mtime = mtime,
        .ctime = ctime,
        .atimensec = atimensec,
        .mtimensec = mtimensec,
        .ctimensec = ctimensec,
        .mode = mode,
        .unused4 = unused4,
        .uid = uid,
        .gid = gid,
        .unused5 = unused5,
    };
}

fn parseRelease(payload: []const u8) !FuseReleaseIn {
    var offset: usize = 0;
    const fh = try readU64(payload, &offset);
    const flags = try readU32(payload, &offset);
    const release_flags = try readU32(payload, &offset);
    const lock_owner = try readU64(payload, &offset);
    return .{ .fh = fh, .flags = flags, .release_flags = release_flags, .lock_owner = lock_owner };
}

fn parseName(payload: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, payload, 0)) |idx| {
        return payload[0..idx];
    }
    return payload;
}

fn alignDirent(len: usize) usize {
    return (len + 7) & ~@as(usize, 7);
}

fn errnoFromResponse(err: i32) std.os.linux.E {
    const code: i32 = if (err < 0) -err else err;
    return @enumFromInt(@as(u16, @intCast(code)));
}

fn sendError(fd: std.posix.fd_t, unique: u64, err: std.os.linux.E) !void {
    var out = FuseOutHeader{
        .len = @sizeOf(FuseOutHeader),
        .@"error" = -@as(i32, @intCast(@intFromEnum(err))),
        .unique = unique,
    };
    try writeAll(fd, std.mem.asBytes(&out));
}

fn sendResponse(fd: std.posix.fd_t, unique: u64, err: i32, payload: []const u8) !void {
    var out = FuseOutHeader{
        .len = @intCast(@sizeOf(FuseOutHeader) + payload.len),
        .@"error" = err,
        .unique = unique,
    };

    try writeAll(fd, std.mem.asBytes(&out));
    if (payload.len > 0) {
        try writeAll(fd, payload);
    }
}

fn writeAll(fd: std.posix.fd_t, data: []const u8) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const n = try std.posix.write(fd, data[offset..]);
        if (n == 0) return error.EndOfStream;
        offset += n;
    }
}

fn readU32(buf: []const u8, offset: *usize) !u32 {
    if (offset.* + 4 > buf.len) return error.InvalidRequest;
    const value = readIntLittle(u32, buf[offset.* .. offset.* + 4]);
    offset.* += 4;
    return value;
}

fn readU64(buf: []const u8, offset: *usize) !u64 {
    if (offset.* + 8 > buf.len) return error.InvalidRequest;
    const value = readIntLittle(u64, buf[offset.* .. offset.* + 8]);
    offset.* += 8;
    return value;
}

fn readIntLittle(comptime T: type, bytes: []const u8) T {
    const ptr: *const [@sizeOf(T)]u8 = @ptrCast(bytes.ptr);
    return std.mem.readInt(T, ptr, .little);
}

fn expectMap(value: cbor.Value) ![]cbor.Entry {
    return switch (value) {
        .Map => |entries| entries,
        else => error.InvalidResponse,
    };
}

fn expectArray(value: cbor.Value) ![]cbor.Value {
    return switch (value) {
        .Array => |entries| entries,
        else => error.InvalidResponse,
    };
}

fn expectText(value: cbor.Value) ![]const u8 {
    return switch (value) {
        .Text => |text| text,
        else => error.InvalidResponse,
    };
}

fn expectBytes(value: cbor.Value) ![]const u8 {
    return switch (value) {
        .Bytes => |bytes| bytes,
        else => error.InvalidResponse,
    };
}

fn getMapU64(map: []cbor.Entry, key: []const u8) ?u64 {
    const value = cbor.getMapValue(map, key) orelse return null;
    return switch (value) {
        .Int => |v| if (v >= 0) @intCast(v) else null,
        else => null,
    };
}

fn getMapU32(map: []cbor.Entry, key: []const u8) ?u32 {
    const value = getMapU64(map, key) orelse return null;
    return @intCast(value);
}

const ParsedEntry = struct {
    out: FuseEntryOut,
    attr: FuseAttr,
};

fn parseEntry(entry_map: []cbor.Entry, default_attr_ttl: u64, default_entry_ttl: u64) !ParsedEntry {
    const ino = getMapU64(entry_map, "ino") orelse return error.InvalidResponse;
    const attr_val = cbor.getMapValue(entry_map, "attr") orelse return error.InvalidResponse;
    const attr_map = try expectMap(attr_val);
    const attr = try parseAttr(attr_map, ino);

    const attr_ttl_ms = getMapU64(entry_map, "attr_ttl_ms") orelse default_attr_ttl;
    const entry_ttl_ms = getMapU64(entry_map, "entry_ttl_ms") orelse default_entry_ttl;

    const out = buildEntry(attr, attr_ttl_ms, entry_ttl_ms);
    return .{ .out = out, .attr = attr };
}

fn parseAttr(attr_map: []cbor.Entry, fallback_ino: u64) !FuseAttr {
    const ino = getMapU64(attr_map, "ino") orelse fallback_ino;
    const size = getMapU64(attr_map, "size") orelse 0;
    const blocks = getMapU64(attr_map, "blocks") orelse ((size + 511) / 512);
    const atime_ms = getMapU64(attr_map, "atime_ms") orelse 0;
    const mtime_ms = getMapU64(attr_map, "mtime_ms") orelse 0;
    const ctime_ms = getMapU64(attr_map, "ctime_ms") orelse 0;
    const mode = getMapU32(attr_map, "mode") orelse 0;
    const nlink = getMapU32(attr_map, "nlink") orelse 1;
    const uid = getMapU32(attr_map, "uid") orelse 0;
    const gid = getMapU32(attr_map, "gid") orelse 0;
    const rdev = getMapU32(attr_map, "rdev") orelse 0;
    const blksize = getMapU32(attr_map, "blksize") orelse 4096;

    const at = msToTimespec(atime_ms);
    const mt = msToTimespec(mtime_ms);
    const ct = msToTimespec(ctime_ms);

    return FuseAttr{
        .ino = ino,
        .size = size,
        .blocks = blocks,
        .atime = at.sec,
        .mtime = mt.sec,
        .ctime = ct.sec,
        .atimensec = at.nsec,
        .mtimensec = mt.nsec,
        .ctimensec = ct.nsec,
        .mode = mode,
        .nlink = nlink,
        .uid = uid,
        .gid = gid,
        .rdev = rdev,
        .blksize = blksize,
        .padding = 0,
    };
}

fn buildEntry(attr: FuseAttr, attr_ttl_ms: u64, entry_ttl_ms: u64) FuseEntryOut {
    const attr_ttl = msToTimespec(attr_ttl_ms);
    const entry_ttl = msToTimespec(entry_ttl_ms);
    return .{
        .nodeid = attr.ino,
        .generation = 0,
        .entry_valid = entry_ttl.sec,
        .attr_valid = attr_ttl.sec,
        .entry_valid_nsec = entry_ttl.nsec,
        .attr_valid_nsec = attr_ttl.nsec,
        .attr = attr,
    };
}

fn buildAttrOut(attr: FuseAttr, attr_ttl_ms: u64) FuseAttrOut {
    const ttl = msToTimespec(attr_ttl_ms);
    return .{
        .attr_valid = ttl.sec,
        .attr_valid_nsec = ttl.nsec,
        .dummy = 0,
        .attr = attr,
    };
}

fn msToTimespec(ms: u64) struct { sec: u64, nsec: u32 } {
    return .{ .sec = ms / 1000, .nsec = @intCast((ms % 1000) * 1_000_000) };
}

fn defaultDirAttr(ino: u64) FuseAttr {
    return .{
        .ino = ino,
        .size = 0,
        .blocks = 0,
        .atime = 0,
        .mtime = 0,
        .ctime = 0,
        .atimensec = 0,
        .mtimensec = 0,
        .ctimensec = 0,
        .mode = 0o40755,
        .nlink = 2,
        .uid = 0,
        .gid = 0,
        .rdev = 0,
        .blksize = 4096,
        .padding = 0,
    };
}
