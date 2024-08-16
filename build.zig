
const std = @import("std");
const print = @import("std").debug.print;

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    const build_shared_libs = b.option(bool, "BUILD_SHARED_LIBS",
                "Build shared libraries (otherwise static ones)") orelse true;

    const dep_pcre2 = b.dependency("pcre2", .{
        .target = target,
        .optimize = optimize,
        .linkage = .static, // TODO: condition on BUILD_SHARED_LIBS
    });

    const ly_config_header = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("src/ly_config.h.in") },
        .include_path = "ly_config.h"
        }, .{
        .LYD_VALUE_SIZE=256,
        .CMAKE_SHARED_MODULE_SUFFIX=".so", // TODO: .dylib for macos and .dll? for windows
        .PLUGINS_DIR_TYPES="", // TODO: fill in the correct path
        .PLUGINS_DIR_EXTENSIONS="", // TODO: fill in the correct path
    });

    const compat_header = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("compat/compat.h.in") },
        .include_path = "compat.h"
        }, .{
        .HAVE_GMTIME_R=1,
        .HAVE_LOCALTIME_R=1,
        .HAVE_REALPATH=1,
        .HAVE_SETENV=1,
        .HAVE_STRDUPA=1,
    });

    const version_header = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("src/version.h.in") },
        .include_path = "version.h"
        }, .{
        .LIBYANG_MAJOR_VERSION=3,
        .LIBYANG_MINOR_VERSION=1,
        .LIBYANG_MICRO_VERSION=0,
        .LIBYANG_VERSION="3.1.0",
        .LIBYANG_MAJOR_SOVERSION=3,
        .LIBYANG_MINOR_SOVERSION=2,
        .LIBYANG_MICRO_SOVERSION=0,
        .LIBYANG_SOVERSION_FULL="3.2.0",
        .LIBYANG_SOVERSION="3",
    });


    var lib = b.addStaticLibrary(.{
        .name = "yang",
        .target = target,
        .optimize = optimize,
    });
    if (build_shared_libs) {
        lib = b.addSharedLibrary(.{
            .name = "yang",
            .target = target,
            .optimize = optimize,
        });
    }

    lib.addConfigHeader(ly_config_header);
    lib.addConfigHeader(compat_header);
    lib.addConfigHeader(version_header);

    var source_files = std.ArrayList([]const u8).init(b.allocator);
    defer source_files.deinit();
    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    flags.append("-std=c11") catch unreachable;

    // Main library source files
    source_files.appendSlice(&.{
        "src/ly_common.c",
        "src/log.c",
        "src/hash_table.c",
        "src/dict.c",
        "src/set.c",
        "src/path.c",
        "src/diff.c",
        "src/context.c",
        "src/json.c",
        "src/tree_data.c",
        "src/tree_data_free.c",
        "src/tree_data_common.c",
        "src/tree_data_hash.c",
        "src/tree_data_new.c",
        "src/parser_xml.c",
        "src/parser_json.c",
        "src/parser_lyb.c",
        "src/out.c",
        "src/printer_data.c",
        "src/printer_xml.c",
        "src/printer_json.c",
        "src/printer_lyb.c",
        "src/schema_compile.c",
        "src/schema_compile_node.c",
        "src/schema_compile_amend.c",
        "src/schema_features.c",
        "src/tree_data_sorted.c",
        "src/tree_schema.c",
        "src/tree_schema_free.c",
        "src/tree_schema_common.c",
        "src/in.c",
        "src/lyb.c",
        "src/parser_common.c",
        "src/parser_yang.c",
        "src/parser_yin.c",
        "src/printer_schema.c",
        "src/printer_yang.c",
        "src/printer_yin.c",
        "src/printer_tree.c",
        "src/plugins.c",
        "src/plugins_types.c",
        "src/plugins_exts.c",
        "src/plugins_exts/metadata.c",
        "src/plugins_exts/nacm.c",
        "src/plugins_exts/yangdata.c",
        "src/plugins_exts/schema_mount.c",
        "src/plugins_exts/structure.c",
        "src/xml.c",
        "src/xpath.c",
        "src/validation.c"
    }) catch unreachable;

    // Type plugins
    source_files.appendSlice(&.{
        "src/plugins_types/binary.c",
        "src/plugins_types/bits.c",
        "src/plugins_types/boolean.c",
        "src/plugins_types/decimal64.c",
        "src/plugins_types/empty.c",
        "src/plugins_types/enumeration.c",
        "src/plugins_types/identityref.c",
        "src/plugins_types/instanceid.c",
        "src/plugins_types/instanceid_keys.c",
        "src/plugins_types/integer.c",
        "src/plugins_types/leafref.c",
        "src/plugins_types/lyds_tree.c",
        "src/plugins_types/string.c",
        "src/plugins_types/union.c",
        "src/plugins_types/ipv4_address.c",
        "src/plugins_types/ipv4_address_no_zone.c",
        "src/plugins_types/ipv6_address.c",
        "src/plugins_types/ipv6_address_no_zone.c",
        "src/plugins_types/ipv4_prefix.c",
        "src/plugins_types/ipv6_prefix.c",
        "src/plugins_types/date_and_time.c",
        "src/plugins_types/hex_string.c",
        "src/plugins_types/xpath1.0.c",
        "src/plugins_types/node_instanceid.c"
    }) catch unreachable;

    source_files.appendSlice(&.{
        "compat/compat.c",
        "compat/strptime.c",
    }) catch unreachable;

    lib.addCSourceFiles(.{
        .files = source_files.items,
        .flags = flags.items,
    });

    lib.addIncludePath(b.path("src"));
    lib.addIncludePath(b.path("src/plugins_exts"));
    lib.linkLibrary(dep_pcre2.artifact("pcre2-8"));
    lib.linkLibC();

    lib.installHeader(b.path("src/context.h"), "libyang/context.h");
    lib.installHeader(b.path("src/dict.h"), "libyang/dict.h");
    lib.installHeader(b.path("src/hash_table.h"), "libyang/hash_table.h");
    lib.installHeader(b.path("src/in.h"), "libyang/in.h");
    lib.installHeader(b.path("src/libyang.h"), "libyang/libyang.h");
    lib.installHeader(b.path("src/log.h"), "libyang/log.h");
    lib.installHeader(ly_config_header.getOutput(), "libyang/ly_config.h");
    lib.installHeader(b.path("src/plugins_exts/metadata.h"), "libyang/metadata.h");
    lib.installHeader(b.path("src/out.h"), "libyang/out.h");
    lib.installHeader(b.path("src/parser_data.h"), "libyang/parser_data.h");
    lib.installHeader(b.path("src/parser_schema.h"), "libyang/parser_schema.h");
    lib.installHeader(b.path("src/plugins_exts.h"), "libyang/plugins_exts.h");
    lib.installHeader(b.path("src/plugins.h"), "libyang/plugins.h");
    lib.installHeader(b.path("src/plugins_types.h"), "libyang/plugins_types.h");
    lib.installHeader(b.path("src/printer_data.h"), "libyang/printer_data.h");
    lib.installHeader(b.path("src/printer_schema.h"), "libyang/printer_schema.h");
    lib.installHeader(b.path("src/set.h"), "libyang/set.h");
    lib.installHeader(b.path("src/tree_data.h"), "libyang/tree_data.h");
    lib.installHeader(b.path("src/tree_edit.h"), "libyang/tree_edit.h");
    lib.installHeader(b.path("src/tree.h"), "libyang/tree.h");
    lib.installHeader(b.path("src/tree_schema.h"), "libyang/tree_schema.h");
    lib.installHeader(version_header.getOutput(), "libyang/version.h");

    b.installArtifact(lib);

    const yanglint = b.addExecutable(.{
        .name = "yanglint",
        .target = target,
        .optimize = optimize,
    });
    yanglint.addCSourceFiles(.{
        .files = &[_][]const u8{
            "tools/lint/main_ni.c",
            "tools/lint/cmd.c",
            "tools/lint/cmd_add.c",
            "tools/lint/cmd_clear.c",
            "tools/lint/cmd_data.c",
            "tools/lint/cmd_list.c",
            "tools/lint/cmd_feature.c",
            "tools/lint/cmd_load.c",
            "tools/lint/cmd_print.c",
            "tools/lint/cmd_searchpath.c",
            "tools/lint/cmd_extdata.c",
            "tools/lint/cmd_help.c",
            "tools/lint/cmd_verb.c",
            "tools/lint/cmd_debug.c",
            "tools/lint/yl_opt.c",
            "tools/lint/yl_schema_features.c",
            "tools/lint/common.c"
        },
        .flags = &[_][]const u8{
        },
    });
    // TODO: add & check interactive flag

    const tool_config_header = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("tools/config.h.in") },
        .include_path = "tools/config.h"
        }, .{
        .LYD_VALUE_SIZE=256,
        .LIBYANG_VERSION="3.1.0",
    });

    yanglint.addCSourceFiles(.{
        .files = &[_][]const u8{
            "tools/lint/main.c",
            "tools/lint/completion.c",
            "tools/lint/configuration.c",
            "tools/lint/linenoise/linenoise.c",
        },
        .flags = &[_][]const u8{
        },
    });
    yanglint.addConfigHeader(compat_header);
    yanglint.addConfigHeader(ly_config_header);
    yanglint.addConfigHeader(tool_config_header);
    yanglint.addIncludePath(b.path("src"));
    yanglint.addIncludePath(b.path("src/plugins_exts"));
    yanglint.installLibraryHeaders(lib);
    yanglint.linkLibrary(lib);
    yanglint.linkLibrary(dep_pcre2.artifact("pcre2-8"));
    yanglint.linkLibC();
    b.installArtifact(yanglint);

    // TODO: tests, docs etc?
}
