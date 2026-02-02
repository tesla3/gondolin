const std = @import("std");
const protocol = @import("sandboxd").protocol;

const log = std.log.scoped(.sandboxd);

const Termination = struct {
    exit_code: i32,
    signal: ?i32,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var virtio = try std.fs.openFileAbsolute("/dev/vport0p0", .{ .mode = .read_write });
    defer virtio.close();
    const virtio_fd: std.posix.fd_t = virtio.handle;

    while (true) {
        const frame = protocol.readFrame(allocator, virtio_fd) catch |err| {
            if (err == error.EndOfStream) break;
            log.err("failed to read frame: {s}", .{@errorName(err)});
            continue;
        };
        defer allocator.free(frame);

        const req = protocol.decodeExecRequest(allocator, frame) catch |err| {
            log.err("invalid exec_request: {s}", .{@errorName(err)});
            _ = protocol.sendError(allocator, virtio_fd, 0, "invalid_request", "invalid exec_request") catch {};
            continue;
        };
        defer {
            allocator.free(req.argv);
            allocator.free(req.env);
        }

        handleExec(allocator, virtio_fd, req) catch |err| {
            log.err("exec handling failed: {s}", .{@errorName(err)});
            _ = protocol.sendError(allocator, virtio_fd, req.id, "exec_failed", "failed to execute") catch {};
        };
    }
}

fn handleExec(allocator: std.mem.Allocator, virtio_fd: std.posix.fd_t, req: protocol.ExecRequest) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    const argv = try buildArgv(arena_alloc, req.cmd, req.argv);
    const envp = try buildEnvp(arena_alloc, allocator, req.env);

    const stdout_pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        std.posix.close(stdout_pipe[0]);
        std.posix.close(stdout_pipe[1]);
    }

    const stderr_pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
    errdefer {
        std.posix.close(stderr_pipe[0]);
        std.posix.close(stderr_pipe[1]);
    }

    var stdin_pipe: ?[2]std.posix.fd_t = null;
    if (req.stdin) {
        stdin_pipe = try std.posix.pipe2(.{ .CLOEXEC = true });
        errdefer {
            std.posix.close(stdin_pipe.?[0]);
            std.posix.close(stdin_pipe.?[1]);
        }
    }

    const pid = try std.posix.fork();
    if (pid == 0) {
        if (req.stdin) {
            try std.posix.dup2(stdin_pipe.?[0], std.posix.STDIN_FILENO);
        } else {
            const devnull = std.posix.openZ("/dev/null", .{ .ACCMODE = .RDONLY }, 0) catch std.posix.exit(127);
            try std.posix.dup2(devnull, std.posix.STDIN_FILENO);
            std.posix.close(devnull);
        }

        try std.posix.dup2(stdout_pipe[1], std.posix.STDOUT_FILENO);
        try std.posix.dup2(stderr_pipe[1], std.posix.STDERR_FILENO);

        std.posix.close(stdout_pipe[0]);
        std.posix.close(stdout_pipe[1]);
        std.posix.close(stderr_pipe[0]);
        std.posix.close(stderr_pipe[1]);

        if (req.stdin) {
            std.posix.close(stdin_pipe.?[0]);
            std.posix.close(stdin_pipe.?[1]);
        }

        if (req.cwd) |cwd| {
            _ = std.posix.chdir(cwd) catch std.posix.exit(127);
        }

        std.posix.execvpeZ(argv[0].?, argv, envp) catch {
            const msg = "exec failed\n";
            _ = std.posix.write(std.posix.STDERR_FILENO, msg) catch {};
            std.posix.exit(127);
        };
    }

    std.posix.close(stdout_pipe[1]);
    std.posix.close(stderr_pipe[1]);

    var stdin_fd: ?std.posix.fd_t = null;
    if (req.stdin) {
        std.posix.close(stdin_pipe.?[0]);
        stdin_fd = stdin_pipe.?[1];
    }

    const original_flags = try std.posix.fcntl(virtio_fd, std.posix.F.GETFL, 0);
    const nonblock_flag_u32: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    const nonblock_flag: usize = @intCast(nonblock_flag_u32);
    _ = try std.posix.fcntl(virtio_fd, std.posix.F.SETFL, original_flags | nonblock_flag);
    defer _ = std.posix.fcntl(virtio_fd, std.posix.F.SETFL, original_flags) catch {};

    var writer = protocol.FrameWriter.init(allocator);
    defer writer.deinit();

    var stdin_reader = protocol.FrameReader.init(allocator);
    defer stdin_reader.deinit();

    var stdout_open = true;
    var stderr_open = true;
    var stdin_open = req.stdin;

    var status: ?u32 = null;
    var buffer: [8192]u8 = undefined;

    const max_buffered: usize = 256 * 1024;

    while (true) {
        if (status != null and !stdout_open and !stderr_open and !writer.hasPending()) break;

        var pollfds: [3]std.posix.pollfd = undefined;
        var nfds: usize = 0;
        var stdout_index: ?usize = null;
        var stderr_index: ?usize = null;
        var virtio_index: ?usize = null;

        const backpressure = writer.pendingBytes() >= max_buffered;

        if (stdout_open and !backpressure) {
            stdout_index = nfds;
            pollfds[nfds] = .{ .fd = stdout_pipe[0], .events = std.posix.POLL.IN, .revents = 0 };
            nfds += 1;
        }
        if (stderr_open and !backpressure) {
            stderr_index = nfds;
            pollfds[nfds] = .{ .fd = stderr_pipe[0], .events = std.posix.POLL.IN, .revents = 0 };
            nfds += 1;
        }

        var virtio_events: i16 = 0;
        if (stdin_open) virtio_events |= std.posix.POLL.IN;
        if (writer.hasPending()) virtio_events |= std.posix.POLL.OUT;
        if (virtio_events != 0) {
            virtio_index = nfds;
            pollfds[nfds] = .{ .fd = virtio_fd, .events = virtio_events, .revents = 0 };
            nfds += 1;
        }

        if (nfds == 0) {
            if (status == null) {
                status = std.posix.waitpid(pid, 0).status;
            }
            continue;
        }

        _ = try std.posix.poll(pollfds[0..nfds], 100);

        if (stdout_index) |sindex| {
            const revents = pollfds[sindex].revents;
            if ((revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) != 0) {
                const n = try std.posix.read(stdout_pipe[0], buffer[0..]);
                if (n == 0) {
                    stdout_open = false;
                    std.posix.close(stdout_pipe[0]);
                } else {
                    const payload = try protocol.encodeExecOutput(allocator, req.id, "stdout", buffer[0..n]);
                    defer allocator.free(payload);
                    try writer.enqueue(payload);
                    try writer.flush(virtio_fd);
                }
            }
        }

        if (stderr_index) |sindex| {
            const revents = pollfds[sindex].revents;
            if ((revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) != 0) {
                const n = try std.posix.read(stderr_pipe[0], buffer[0..]);
                if (n == 0) {
                    stderr_open = false;
                    std.posix.close(stderr_pipe[0]);
                } else {
                    const payload = try protocol.encodeExecOutput(allocator, req.id, "stderr", buffer[0..n]);
                    defer allocator.free(payload);
                    try writer.enqueue(payload);
                    try writer.flush(virtio_fd);
                }
            }
        }

        if (virtio_index) |vindex| {
            const revents = pollfds[vindex].revents;
            if ((revents & std.posix.POLL.OUT) != 0) {
                try writer.flush(virtio_fd);
            }
            if (stdin_open and (revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) != 0) {
                stdin_open = handleStdin(allocator, &stdin_reader, virtio_fd, stdin_fd.?, req.id) catch |err| blk: {
                    log.err("stdin handling failed: {s}", .{@errorName(err)});
                    if (stdin_fd) |fd| std.posix.close(fd);
                    break :blk false;
                };
                if (!stdin_open) stdin_fd = null;
            }
        }

        if (status == null) {
            const res = std.posix.waitpid(pid, std.posix.W.NOHANG);
            if (res.pid != 0) {
                status = res.status;
            }
        }
    }

    if (stdin_fd) |fd| std.posix.close(fd);

    if (status == null) {
        status = std.posix.waitpid(pid, 0).status;
    }

    const term = parseStatus(status.?);
    const response = try protocol.encodeExecResponse(allocator, req.id, term.exit_code, term.signal);
    defer allocator.free(response);
    try writer.enqueue(response);
    try flushWriter(virtio_fd, &writer);
}

fn handleStdin(
    allocator: std.mem.Allocator,
    reader: *protocol.FrameReader,
    virtio_fd: std.posix.fd_t,
    stdin_fd: std.posix.fd_t,
    expected_id: u32,
) !bool {
    while (true) {
        const frame = reader.readFrame(virtio_fd) catch |err| {
            if (err == error.EndOfStream) {
                std.posix.close(stdin_fd);
                return false;
            }
            return err;
        };
        if (frame == null) break;

        const frame_buf = frame.?;
        defer allocator.free(frame_buf);

        const data = try protocol.decodeStdinData(allocator, frame_buf, expected_id);
        if (data.data.len > 0) {
            try protocol.writeAll(stdin_fd, data.data);
        }
        if (data.eof) {
            std.posix.close(stdin_fd);
            return false;
        }
    }
    return true;
}

fn flushWriter(virtio_fd: std.posix.fd_t, writer: *protocol.FrameWriter) !void {
    while (writer.hasPending()) {
        var pollfds: [1]std.posix.pollfd = .{.{
            .fd = virtio_fd,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};

        _ = try std.posix.poll(pollfds[0..], 100);
        const revents = pollfds[0].revents;
        if ((revents & std.posix.POLL.OUT) != 0) {
            try writer.flush(virtio_fd);
        }
        if ((revents & std.posix.POLL.HUP) != 0) return error.EndOfStream;
    }
}

fn parseStatus(status: u32) Termination {
    if (std.posix.W.IFEXITED(status)) {
        return .{ .exit_code = @as(i32, @intCast(std.posix.W.EXITSTATUS(status))), .signal = null };
    }
    if (std.posix.W.IFSIGNALED(status)) {
        const sig = @as(i32, @intCast(std.posix.W.TERMSIG(status)));
        return .{ .exit_code = 128 + sig, .signal = sig };
    }
    return .{ .exit_code = 1, .signal = null };
}

fn buildArgv(
    allocator: std.mem.Allocator,
    cmd: []const u8,
    argv: []const []const u8,
) ![*:null]const ?[*:0]const u8 {
    const total = argv.len + 1;
    const argv_buf = try allocator.allocSentinel(?[*:0]const u8, total, null);
    argv_buf[0] = (try allocator.dupeZ(u8, cmd)).ptr;
    for (argv, 0..) |arg, idx| {
        argv_buf[idx + 1] = (try allocator.dupeZ(u8, arg)).ptr;
    }
    return argv_buf.ptr;
}

fn buildEnvp(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    env: []const []const u8,
) ![*:null]const ?[*:0]const u8 {
    if (env.len == 0) {
        return std.c.environ;
    }

    var env_map = try std.process.getEnvMap(allocator);
    defer env_map.deinit();

    for (env) |entry| {
        const sep = std.mem.indexOfScalar(u8, entry, '=') orelse return protocol.ProtocolError.InvalidValue;
        const key = entry[0..sep];
        const value = entry[sep + 1 ..];
        try env_map.put(key, value);
    }

    const total: usize = @intCast(env_map.count());
    const envp_buf = try arena.allocSentinel(?[*:0]const u8, total, null);

    var it = env_map.iterator();
    var idx: usize = 0;
    while (it.next()) |entry| : (idx += 1) {
        const key = entry.key_ptr.*;
        const value = entry.value_ptr.*;
        const full_len = key.len + 1 + value.len;
        var pair = try arena.alloc(u8, full_len + 1);
        std.mem.copyForwards(u8, pair[0..key.len], key);
        pair[key.len] = '=';
        std.mem.copyForwards(u8, pair[key.len + 1 .. key.len + 1 + value.len], value);
        pair[full_len] = 0;
        envp_buf[idx] = pair[0..full_len :0].ptr;
    }

    return envp_buf.ptr;
}
