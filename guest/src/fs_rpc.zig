const std = @import("std");
const cbor = @import("cbor.zig");
const protocol = @import("protocol.zig");

pub const RpcError = error{
    InvalidType,
    MissingField,
    UnexpectedType,
    InvalidValue,
};

pub const FieldValue = union(enum) {
    UInt: u64,
    Int: i64,
    Text: []const u8,
    Bytes: []const u8,
    Bool: bool,
};

pub const Field = struct {
    name: []const u8,
    value: FieldValue,
};

pub const FsResponse = struct {
    allocator: std.mem.Allocator,
    frame: []u8,
    root: cbor.Value,
    op: []const u8,
    err: i32,
    res: ?[]cbor.Entry,
    message: ?[]const u8,

    pub fn deinit(self: *FsResponse) void {
        cbor.freeValue(self.allocator, self.root);
        self.allocator.free(self.frame);
    }
};

pub const FsRpcClient = struct {
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    next_id: u32 = 1,

    pub fn init(allocator: std.mem.Allocator, fd: std.posix.fd_t) FsRpcClient {
        return .{ .allocator = allocator, .fd = fd };
    }

    pub fn request(self: *FsRpcClient, op: []const u8, fields: []const Field) !FsResponse {
        const id = self.next_id;
        self.next_id = if (self.next_id == 0xffffffff) 1 else self.next_id + 1;

        const payload = try encodeRequest(self.allocator, id, op, fields);
        defer self.allocator.free(payload);

        try protocol.writeFrame(self.fd, payload);

        const frame = try protocol.readFrame(self.allocator, self.fd);
        errdefer self.allocator.free(frame);

        var dec = cbor.Decoder.init(self.allocator, frame);
        const root = try dec.decodeValue();
        errdefer cbor.freeValue(self.allocator, root);

        const map = try expectMap(root);
        const msg_type = try expectText(cbor.getMapValue(map, "t") orelse return RpcError.MissingField);
        if (!std.mem.eql(u8, msg_type, "fs_response")) {
            return RpcError.UnexpectedType;
        }

        const payload_val = cbor.getMapValue(map, "p") orelse return RpcError.MissingField;
        const payload_map = try expectMap(payload_val);
        const op_val = try expectText(cbor.getMapValue(payload_map, "op") orelse return RpcError.MissingField);
        const err_val = cbor.getMapValue(payload_map, "err") orelse return RpcError.MissingField;
        const err_int = try expectInt(err_val);
        const res_val = cbor.getMapValue(payload_map, "res");
        const message_val = cbor.getMapValue(payload_map, "message");

        var res_map: ?[]cbor.Entry = null;
        if (res_val) |value| {
            switch (value) {
                .Null => res_map = null,
                else => res_map = try expectMap(value),
            }
        }

        var message_text: ?[]const u8 = null;
        if (message_val) |value| {
            switch (value) {
                .Null => message_text = null,
                .Text => |text| message_text = text,
                else => return RpcError.UnexpectedType,
            }
        }

        return FsResponse{
            .allocator = self.allocator,
            .frame = frame,
            .root = root,
            .op = op_val,
            .err = @intCast(err_int),
            .res = res_map,
            .message = message_text,
        };
    }
};

fn encodeRequest(allocator: std.mem.Allocator, id: u32, op: []const u8, fields: []const Field) ![]u8 {
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);

    const w = buf.writer(allocator);
    try cbor.writeMapStart(w, 4);
    try cbor.writeText(w, "v");
    try cbor.writeUInt(w, 1);
    try cbor.writeText(w, "t");
    try cbor.writeText(w, "fs_request");
    try cbor.writeText(w, "id");
    try cbor.writeUInt(w, id);
    try cbor.writeText(w, "p");
    try cbor.writeMapStart(w, 2);
    try cbor.writeText(w, "op");
    try cbor.writeText(w, op);
    try cbor.writeText(w, "req");
    try cbor.writeMapStart(w, fields.len);
    for (fields) |field| {
        try cbor.writeText(w, field.name);
        try writeFieldValue(w, field.value);
    }

    return try buf.toOwnedSlice(allocator);
}

fn writeFieldValue(writer: anytype, value: FieldValue) !void {
    switch (value) {
        .UInt => |v| try cbor.writeUInt(writer, v),
        .Int => |v| try cbor.writeInt(writer, v),
        .Text => |v| try cbor.writeText(writer, v),
        .Bytes => |v| try cbor.writeBytes(writer, v),
        .Bool => |v| try cbor.writeBool(writer, v),
    }
}

fn expectMap(value: cbor.Value) ![]cbor.Entry {
    return switch (value) {
        .Map => |entries| entries,
        else => RpcError.UnexpectedType,
    };
}

fn expectText(value: cbor.Value) ![]const u8 {
    return switch (value) {
        .Text => |text| text,
        else => RpcError.UnexpectedType,
    };
}

fn expectInt(value: cbor.Value) !i64 {
    return switch (value) {
        .Int => |int| int,
        else => RpcError.UnexpectedType,
    };
}
