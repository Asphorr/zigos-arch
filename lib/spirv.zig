// Comptime SPIR-V Builder
// Generates SPIR-V bytecode at compile time from declarative shader descriptions.
// Eliminates glslc dependency — shaders are pure Zig.

const std = @import("std");

// SPIR-V Opcodes
const Op = struct {
    const Capability: u16 = 17;
    const ExtInstImport: u16 = 11;
    const MemoryModel: u16 = 14;
    const EntryPoint: u16 = 15;
    const ExecutionMode: u16 = 16;
    const Name: u16 = 5;
    const MemberName: u16 = 6;
    const Decorate: u16 = 71;
    const MemberDecorate: u16 = 72;
    const TypeVoid: u16 = 19;
    const TypeFloat: u16 = 22;
    const TypeInt: u16 = 21;
    const TypeVector: u16 = 23;
    const TypeMatrix: u16 = 24;
    const TypePointer: u16 = 32;
    const TypeStruct: u16 = 30;
    const TypeFunction: u16 = 33;
    const TypeArray: u16 = 28;
    const Constant: u16 = 43;
    const Variable: u16 = 59;
    const Function: u16 = 54;
    const FunctionEnd: u16 = 56;
    const Label: u16 = 248;
    const Load: u16 = 61;
    const Store: u16 = 62;
    const AccessChain: u16 = 65;
    const CompositeConstruct: u16 = 80;
    const CompositeExtract: u16 = 81;
    const MatrixTimesVector: u16 = 145;
    const VectorTimesScalar: u16 = 142;
    const Dot: u16 = 148;
    const FMul: u16 = 133;
    const FAdd: u16 = 129;
    const FSub: u16 = 131;
    const FNegate: u16 = 127;
    const Return: u16 = 253;
    const ExtInst: u16 = 12;
};

// Decoration constants
const Decoration = struct {
    const Block: u32 = 2;
    const ColMajor: u32 = 5;
    const MatrixStride: u32 = 7;
    const BuiltIn: u32 = 11;
    const Location: u32 = 30;
    const Offset: u32 = 35;
};

// BuiltIn values
const BuiltIn = struct {
    const Position: u32 = 0;
    const PointSize: u32 = 1;
    const ClipDistance: u32 = 3;
    const CullDistance: u32 = 4;
};

// Storage classes
const StorageClass = struct {
    const Input: u32 = 1;
    const Output: u32 = 3;
    const PushConstant: u32 = 9;
};

pub const VarType = enum { vec3, vec4, mat4 };

pub const VertexShaderDesc = struct {
    inputs: []const VarType,
    outputs: []const VarType,
    push_bytes: u32 = 64,
};

pub const FragmentShaderDesc = struct {
    inputs: []const VarType,
    push_bytes: u32 = 0,
    ambient: f32 = 0.3,
};

const MAX_WORDS = 1024;

pub const ShaderResult = struct {
    data: [MAX_WORDS]u32,
    len: u32,

    pub fn slice(self: *const ShaderResult) []const u32 {
        return self.data[0..self.len];
    }
};

const Builder = struct {
    words: [MAX_WORDS]u32 = [_]u32{0} ** MAX_WORDS,
    pos: u32 = 0,
    next_id: u32 = 1,

    fn emit(self: *Builder, word: u32) void {
        self.words[self.pos] = word;
        self.pos += 1;
    }

    fn emitInst(self: *Builder, opcode: u16, word_count: u16) void {
        self.emit(@as(u32, word_count) << 16 | @as(u32, opcode));
    }

    fn id(self: *Builder) u32 {
        const r = self.next_id;
        self.next_id += 1;
        return r;
    }

    fn emitString(self: *Builder, s: []const u8) u32 {
        // Pack string into u32 words (null terminated, padded)
        var word: u32 = 0;
        var byte_in_word: u5 = 0;
        var count: u32 = 0;
        for (s) |c| {
            word |= @as(u32, c) << (@as(u5, @truncate(byte_in_word)) * 8);
            byte_in_word += 1;
            if (byte_in_word == 4) {
                self.emit(word);
                word = 0;
                byte_in_word = 0;
                count += 1;
            }
        }
        // Null terminator + padding
        self.emit(word); // remaining bytes + null
        count += 1;
        return count;
    }

    fn emitF32(self: *Builder, val: f32) void {
        self.emit(@bitCast(val));
    }

    fn patchWordCount(self: *Builder, inst_pos: u32, word_count: u16) void {
        self.words[inst_pos] = (@as(u32, word_count) << 16) | (self.words[inst_pos] & 0xFFFF);
    }
};

/// Generate a vertex shader with MVP transform and attribute pass-through.
/// Inputs[0] = position (vec3), remaining inputs passed to outputs.
/// Push constant = mat4 MVP (+ optional extra bytes for light dir etc).
pub fn vertexShader(comptime desc: VertexShaderDesc) ShaderResult {
    comptime {
        var b = Builder{};

        // Header
        b.emit(0x07230203); // Magic
        b.emit(0x00010000); // Version 1.0
        b.emit(0); // Generator
        const bound_pos = b.pos;
        b.emit(0); // Bound (patched later)
        b.emit(0); // Reserved

        // OpCapability Shader
        b.emitInst(Op.Capability, 2);
        b.emit(1);

        // OpMemoryModel Logical GLSL450
        b.emitInst(Op.MemoryModel, 3);
        b.emit(0); // Logical
        b.emit(1); // GLSL450

        // Pre-allocate IDs
        const id_void = b.id();
        const id_float = b.id();
        const id_vec3 = b.id();
        const id_vec4 = b.id();
        const id_mat4 = b.id();
        const id_int = b.id();
        const id_fn_void = b.id();
        const id_main = b.id();
        const id_label = b.id();

        // gl_PerVertex struct + variable
        const id_arr1 = b.id(); // float[1] for ClipDistance/CullDistance
        const id_int_1 = b.id(); // const int 1
        const id_gl_struct = b.id();
        const id_ptr_gl_out = b.id();
        const id_gl_var = b.id();
        const id_int_0 = b.id(); // const int 0

        // Push constant struct
        const id_push_struct = b.id();
        const id_ptr_push = b.id();
        const id_push_var = b.id();
        const id_ptr_push_mat4 = b.id();

        // Input/output variable IDs
        var id_in: [8]u32 = undefined;
        for (0..desc.inputs.len) |i| {
            id_in[i] = b.id(); // pointer type
        }
        var id_in_var: [8]u32 = undefined;
        for (0..desc.inputs.len) |i| {
            id_in_var[i] = b.id();
        }
        var id_out_var: [8]u32 = undefined;
        for (0..desc.outputs.len) |i| {
            id_out_var[i] = b.id();
        }
        var id_out: [8]u32 = undefined;
        for (0..desc.outputs.len) |i| {
            id_out[i] = b.id(); // pointer type
        }

        const id_const_1f = b.id();
        const id_ptr_out_vec4 = b.id();

        // --- EntryPoint ---
        const entry_start = b.pos;
        b.emitInst(Op.EntryPoint, 0); // patched
        b.emit(0); // Vertex
        b.emit(id_main);
        _ = b.emitString("main");
        // Interface variables
        b.emit(id_gl_var);
        for (0..desc.inputs.len) |i| b.emit(id_in_var[i]);
        for (0..desc.outputs.len) |i| b.emit(id_out_var[i]);
        b.patchWordCount(entry_start, @intCast(b.pos - entry_start));

        // --- Decorations ---
        // gl_PerVertex block
        b.emitInst(Op.Decorate, 3); b.emit(id_gl_struct); b.emit(Decoration.Block);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_gl_struct); b.emit(0); b.emit(Decoration.BuiltIn); b.emit(BuiltIn.Position);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_gl_struct); b.emit(1); b.emit(Decoration.BuiltIn); b.emit(BuiltIn.PointSize);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_gl_struct); b.emit(2); b.emit(Decoration.BuiltIn); b.emit(BuiltIn.ClipDistance);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_gl_struct); b.emit(3); b.emit(Decoration.BuiltIn); b.emit(BuiltIn.CullDistance);

        // Push constant block
        b.emitInst(Op.Decorate, 3); b.emit(id_push_struct); b.emit(Decoration.Block);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_push_struct); b.emit(0); b.emit(Decoration.ColMajor);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_push_struct); b.emit(0); b.emit(Decoration.Offset); b.emit(0);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_push_struct); b.emit(0); b.emit(Decoration.MatrixStride); b.emit(16);

        // Input locations
        for (0..desc.inputs.len) |i| {
            b.emitInst(Op.Decorate, 4); b.emit(id_in_var[i]); b.emit(Decoration.Location); b.emit(@intCast(i));
        }
        // Output locations
        for (0..desc.outputs.len) |i| {
            b.emitInst(Op.Decorate, 4); b.emit(id_out_var[i]); b.emit(Decoration.Location); b.emit(@intCast(i));
        }

        // --- Types ---
        b.emitInst(Op.TypeVoid, 2); b.emit(id_void);
        b.emitInst(Op.TypeFloat, 3); b.emit(id_float); b.emit(32);
        b.emitInst(Op.TypeVector, 4); b.emit(id_vec3); b.emit(id_float); b.emit(3);
        b.emitInst(Op.TypeVector, 4); b.emit(id_vec4); b.emit(id_float); b.emit(4);
        b.emitInst(Op.TypeMatrix, 4); b.emit(id_mat4); b.emit(id_vec4); b.emit(4);
        b.emitInst(Op.TypeInt, 4); b.emit(id_int); b.emit(32); b.emit(1); // signed
        b.emitInst(Op.TypeFunction, 3); b.emit(id_fn_void); b.emit(id_void);

        // int constants
        b.emitInst(Op.Constant, 4); b.emit(id_int); b.emit(id_int_1); b.emit(1);
        b.emitInst(Op.Constant, 4); b.emit(id_int); b.emit(id_int_0); b.emit(0);

        // float[1] array
        b.emitInst(Op.TypeArray, 4); b.emit(id_arr1); b.emit(id_float); b.emit(id_int_1);

        // gl_PerVertex struct {vec4 Position, float PointSize, float[1] ClipDist, float[1] CullDist}
        b.emitInst(Op.TypeStruct, 6); b.emit(id_gl_struct); b.emit(id_vec4); b.emit(id_float); b.emit(id_arr1); b.emit(id_arr1);
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_gl_out); b.emit(StorageClass.Output); b.emit(id_gl_struct);
        b.emitInst(Op.Variable, 4); b.emit(id_ptr_gl_out); b.emit(id_gl_var); b.emit(StorageClass.Output);

        // Push constant struct {mat4 mvp}
        b.emitInst(Op.TypeStruct, 3); b.emit(id_push_struct); b.emit(id_mat4);
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_push); b.emit(StorageClass.PushConstant); b.emit(id_push_struct);
        b.emitInst(Op.Variable, 4); b.emit(id_ptr_push); b.emit(id_push_var); b.emit(StorageClass.PushConstant);
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_push_mat4); b.emit(StorageClass.PushConstant); b.emit(id_mat4);

        // Input pointer types + variables
        for (0..desc.inputs.len) |i| {
            const type_id = if (desc.inputs[i] == .vec3) id_vec3 else if (desc.inputs[i] == .vec4) id_vec4 else id_mat4;
            b.emitInst(Op.TypePointer, 4); b.emit(id_in[i]); b.emit(StorageClass.Input); b.emit(type_id);
            b.emitInst(Op.Variable, 4); b.emit(id_in[i]); b.emit(id_in_var[i]); b.emit(StorageClass.Input);
        }

        // Output pointer types + variables
        for (0..desc.outputs.len) |i| {
            const type_id = if (desc.outputs[i] == .vec3) id_vec3 else if (desc.outputs[i] == .vec4) id_vec4 else id_mat4;
            b.emitInst(Op.TypePointer, 4); b.emit(id_out[i]); b.emit(StorageClass.Output); b.emit(type_id);
            b.emitInst(Op.Variable, 4); b.emit(id_out[i]); b.emit(id_out_var[i]); b.emit(StorageClass.Output);
        }

        // Constants
        b.emitInst(Op.Constant, 4); b.emit(id_float); b.emit(id_const_1f); b.emitF32(1.0);
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_out_vec4); b.emit(StorageClass.Output); b.emit(id_vec4);

        // --- Function body ---
        b.emitInst(Op.Function, 5); b.emit(id_void); b.emit(id_main); b.emit(0); b.emit(id_fn_void);
        b.emitInst(Op.Label, 2); b.emit(id_label);

        // Load MVP matrix: push.mvp
        const id_mvp_ptr = b.id();
        b.emitInst(Op.AccessChain, 5); b.emit(id_ptr_push_mat4); b.emit(id_mvp_ptr); b.emit(id_push_var); b.emit(id_int_0);
        const id_mvp = b.id();
        b.emitInst(Op.Load, 4); b.emit(id_mat4); b.emit(id_mvp); b.emit(id_mvp_ptr);

        // Load position (input 0)
        const id_pos = b.id();
        b.emitInst(Op.Load, 4); b.emit(id_vec3); b.emit(id_pos); b.emit(id_in_var[0]);

        // Construct vec4(pos, 1.0)
        const id_pos_x = b.id();
        const id_pos_y = b.id();
        const id_pos_z = b.id();
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_pos_x); b.emit(id_pos); b.emit(0);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_pos_y); b.emit(id_pos); b.emit(1);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_pos_z); b.emit(id_pos); b.emit(2);
        const id_pos4 = b.id();
        b.emitInst(Op.CompositeConstruct, 7); b.emit(id_vec4); b.emit(id_pos4); b.emit(id_pos_x); b.emit(id_pos_y); b.emit(id_pos_z); b.emit(id_const_1f);

        // gl_Position = mvp * pos4
        const id_clip = b.id();
        b.emitInst(Op.MatrixTimesVector, 5); b.emit(id_vec4); b.emit(id_clip); b.emit(id_mvp); b.emit(id_pos4);
        const id_gl_pos_ptr = b.id();
        b.emitInst(Op.AccessChain, 5); b.emit(id_ptr_out_vec4); b.emit(id_gl_pos_ptr); b.emit(id_gl_var); b.emit(id_int_0);
        b.emitInst(Op.Store, 3); b.emit(id_gl_pos_ptr); b.emit(id_clip);

        // Pass remaining inputs to outputs (skip input 0 = position)
        // outputs[i] = inputs[i + 1]
        for (0..desc.outputs.len) |i| {
            const src_idx = i + 1; // skip position
            if (src_idx < desc.inputs.len) {
                const type_id = if (desc.inputs[src_idx] == .vec3) id_vec3 else id_vec4;
                const id_val = b.id();
                b.emitInst(Op.Load, 4); b.emit(type_id); b.emit(id_val); b.emit(id_in_var[src_idx]);
                b.emitInst(Op.Store, 3); b.emit(id_out_var[i]); b.emit(id_val);
            }
        }

        b.emitInst(Op.Return, 1);
        b.emitInst(Op.FunctionEnd, 1);

        // Patch bound
        b.words[bound_pos] = b.next_id;

        return .{ .data = b.words, .len = b.pos };
    }
}

/// Generate a fragment shader with diffuse lighting.
/// Inputs[0] = color (vec3), inputs[1] = normal (vec3).
/// Push constant contains light direction at offset 64 (vec4).
pub fn fragmentShaderLit(comptime desc: FragmentShaderDesc) ShaderResult {
    comptime {
        var b = Builder{};

        // Header
        b.emit(0x07230203);
        b.emit(0x00010000);
        b.emit(0);
        const bound_pos = b.pos;
        b.emit(0);
        b.emit(0);

        // Capability
        b.emitInst(Op.Capability, 2); b.emit(1);

        // Pre-allocate IDs (must happen before any emission that uses them)
        const id_void = b.id();
        const id_float = b.id();
        const id_vec3 = b.id();
        const id_vec4 = b.id();
        const id_fn_void = b.id();
        const id_main = b.id();
        const id_label = b.id();

        // Output
        const id_ptr_out_vec4 = b.id();
        const id_out_var = b.id();

        // Inputs
        var id_in_ptr: [8]u32 = undefined;
        var id_in_var: [8]u32 = undefined;
        for (0..desc.inputs.len) |i| {
            id_in_ptr[i] = b.id();
            id_in_var[i] = b.id();
        }

        // Push constant for light dir
        const id_push_struct = b.id();
        const id_ptr_push = b.id();
        const id_push_var = b.id();
        const id_mat4 = b.id();
        const id_int = b.id();
        const id_int_1 = b.id(); // index 1 for lightDir in push struct
        const id_ptr_push_vec4 = b.id();

        const id_const_0f = b.id();
        const id_const_1f = b.id();
        const id_const_ambient = b.id();
        const id_const_diffuse = b.id();

        // GLSL.std.450 import for Normalize, FMax
        const id_glsl = b.id();

        // ExtInstImport MUST come before MemoryModel (SPIR-V logical layout section 2.4)
        const glsl_start = b.pos;
        b.emitInst(Op.ExtInstImport, 0);
        b.emit(id_glsl);
        const str_words = b.emitString("GLSL.std.450");
        b.patchWordCount(glsl_start, @intCast(2 + str_words));

        // MemoryModel
        b.emitInst(Op.MemoryModel, 3); b.emit(0); b.emit(1);

        // EntryPoint
        const entry_start = b.pos;
        b.emitInst(Op.EntryPoint, 0);
        b.emit(4); // Fragment
        b.emit(id_main);
        _ = b.emitString("main");
        b.emit(id_out_var);
        for (0..desc.inputs.len) |i| b.emit(id_in_var[i]);
        b.patchWordCount(entry_start, @intCast(b.pos - entry_start));

        // ExecutionMode OriginUpperLeft
        b.emitInst(Op.ExecutionMode, 3); b.emit(id_main); b.emit(7);

        // Decorations
        b.emitInst(Op.Decorate, 4); b.emit(id_out_var); b.emit(Decoration.Location); b.emit(0);
        for (0..desc.inputs.len) |i| {
            b.emitInst(Op.Decorate, 4); b.emit(id_in_var[i]); b.emit(Decoration.Location); b.emit(@intCast(i));
        }
        // Push constant decorations
        b.emitInst(Op.Decorate, 3); b.emit(id_push_struct); b.emit(Decoration.Block);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_push_struct); b.emit(0); b.emit(Decoration.Offset); b.emit(0);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_push_struct); b.emit(0); b.emit(Decoration.ColMajor);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_push_struct); b.emit(0); b.emit(Decoration.MatrixStride); b.emit(16);
        b.emitInst(Op.MemberDecorate, 5); b.emit(id_push_struct); b.emit(1); b.emit(Decoration.Offset); b.emit(64);

        // Types
        b.emitInst(Op.TypeVoid, 2); b.emit(id_void);
        b.emitInst(Op.TypeFloat, 3); b.emit(id_float); b.emit(32);
        b.emitInst(Op.TypeVector, 4); b.emit(id_vec3); b.emit(id_float); b.emit(3);
        b.emitInst(Op.TypeVector, 4); b.emit(id_vec4); b.emit(id_float); b.emit(4);
        b.emitInst(Op.TypeMatrix, 4); b.emit(id_mat4); b.emit(id_vec4); b.emit(4);
        b.emitInst(Op.TypeInt, 4); b.emit(id_int); b.emit(32); b.emit(1);
        b.emitInst(Op.TypeFunction, 3); b.emit(id_fn_void); b.emit(id_void);

        // Output variable
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_out_vec4); b.emit(StorageClass.Output); b.emit(id_vec4);
        b.emitInst(Op.Variable, 4); b.emit(id_ptr_out_vec4); b.emit(id_out_var); b.emit(StorageClass.Output);

        // Input variables
        for (0..desc.inputs.len) |i| {
            const tid = if (desc.inputs[i] == .vec3) id_vec3 else id_vec4;
            b.emitInst(Op.TypePointer, 4); b.emit(id_in_ptr[i]); b.emit(StorageClass.Input); b.emit(tid);
            b.emitInst(Op.Variable, 4); b.emit(id_in_ptr[i]); b.emit(id_in_var[i]); b.emit(StorageClass.Input);
        }

        // Push constant struct {mat4 mvp; vec4 lightDir}
        b.emitInst(Op.TypeStruct, 4); b.emit(id_push_struct); b.emit(id_mat4); b.emit(id_vec4);
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_push); b.emit(StorageClass.PushConstant); b.emit(id_push_struct);
        b.emitInst(Op.Variable, 4); b.emit(id_ptr_push); b.emit(id_push_var); b.emit(StorageClass.PushConstant);
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_push_vec4); b.emit(StorageClass.PushConstant); b.emit(id_vec4);

        // Constants
        b.emitInst(Op.Constant, 4); b.emit(id_int); b.emit(id_int_1); b.emit(1);
        b.emitInst(Op.Constant, 4); b.emit(id_float); b.emit(id_const_0f); b.emitF32(0.0);
        b.emitInst(Op.Constant, 4); b.emit(id_float); b.emit(id_const_1f); b.emitF32(1.0);
        b.emitInst(Op.Constant, 4); b.emit(id_float); b.emit(id_const_ambient); b.emitF32(desc.ambient);
        b.emitInst(Op.Constant, 4); b.emit(id_float); b.emit(id_const_diffuse); b.emitF32(1.0 - desc.ambient);

        // --- Function body ---
        b.emitInst(Op.Function, 5); b.emit(id_void); b.emit(id_main); b.emit(0); b.emit(id_fn_void);
        b.emitInst(Op.Label, 2); b.emit(id_label);

        // Load color (input 0)
        const id_color = b.id();
        b.emitInst(Op.Load, 4); b.emit(id_vec3); b.emit(id_color); b.emit(id_in_var[0]);

        // Load normal (input 1)
        const id_normal = b.id();
        b.emitInst(Op.Load, 4); b.emit(id_vec3); b.emit(id_normal); b.emit(id_in_var[1]);

        // Normalize normal: GLSL.std.450 Normalize (69)
        const id_norm = b.id();
        b.emitInst(Op.ExtInst, 6); b.emit(id_vec3); b.emit(id_norm); b.emit(id_glsl); b.emit(69); b.emit(id_normal);

        // Load light direction from push constant
        const id_light_ptr = b.id();
        b.emitInst(Op.AccessChain, 5); b.emit(id_ptr_push_vec4); b.emit(id_light_ptr); b.emit(id_push_var); b.emit(id_int_1);
        const id_light4 = b.id();
        b.emitInst(Op.Load, 4); b.emit(id_vec4); b.emit(id_light4); b.emit(id_light_ptr);

        // Extract vec3 from lightDir vec4
        const id_lx = b.id();
        const id_ly = b.id();
        const id_lz = b.id();
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_lx); b.emit(id_light4); b.emit(0);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_ly); b.emit(id_light4); b.emit(1);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_lz); b.emit(id_light4); b.emit(2);
        const id_light3 = b.id();
        b.emitInst(Op.CompositeConstruct, 6); b.emit(id_vec3); b.emit(id_light3); b.emit(id_lx); b.emit(id_ly); b.emit(id_lz);

        // dot(normal, lightDir)
        const id_dot = b.id();
        b.emitInst(Op.Dot, 5); b.emit(id_float); b.emit(id_dot); b.emit(id_norm); b.emit(id_light3);

        // max(dot, 0.0) — GLSL.std.450 FMax (40)
        const id_clamped = b.id();
        b.emitInst(Op.ExtInst, 7); b.emit(id_float); b.emit(id_clamped); b.emit(id_glsl); b.emit(40); b.emit(id_dot); b.emit(id_const_0f);

        // brightness = ambient + diffuse_scale * clamped
        const id_scaled = b.id();
        b.emitInst(Op.FMul, 5); b.emit(id_float); b.emit(id_scaled); b.emit(id_const_diffuse); b.emit(id_clamped);
        const id_brightness = b.id();
        b.emitInst(Op.FAdd, 5); b.emit(id_float); b.emit(id_brightness); b.emit(id_const_ambient); b.emit(id_scaled);

        // lit_color = color * brightness (per-component)
        const id_bright_vec = b.id();
        b.emitInst(Op.CompositeConstruct, 6); b.emit(id_vec3); b.emit(id_bright_vec); b.emit(id_brightness); b.emit(id_brightness); b.emit(id_brightness);
        const id_lit = b.id();
        b.emitInst(Op.FMul, 5); b.emit(id_vec3); b.emit(id_lit); b.emit(id_color); b.emit(id_bright_vec);

        // Construct vec4(lit, 1.0)
        const id_lit_x = b.id();
        const id_lit_y = b.id();
        const id_lit_z = b.id();
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_lit_x); b.emit(id_lit); b.emit(0);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_lit_y); b.emit(id_lit); b.emit(1);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_lit_z); b.emit(id_lit); b.emit(2);
        const id_out_color = b.id();
        b.emitInst(Op.CompositeConstruct, 7); b.emit(id_vec4); b.emit(id_out_color); b.emit(id_lit_x); b.emit(id_lit_y); b.emit(id_lit_z); b.emit(id_const_1f);

        // Store output
        b.emitInst(Op.Store, 3); b.emit(id_out_var); b.emit(id_out_color);

        b.emitInst(Op.Return, 1);
        b.emitInst(Op.FunctionEnd, 1);

        b.words[bound_pos] = b.next_id;
        return .{ .data = b.words, .len = b.pos };
    }
}

/// Simple fragment shader — pass-through color to output.
pub fn fragmentShaderPass(comptime _: u32) ShaderResult {
    comptime {
        var b = Builder{};

        b.emit(0x07230203); b.emit(0x00010000); b.emit(0);
        const bound_pos = b.pos; b.emit(0); b.emit(0);

        b.emitInst(Op.Capability, 2); b.emit(1);
        b.emitInst(Op.MemoryModel, 3); b.emit(0); b.emit(1);

        const id_void = b.id();
        const id_float = b.id();
        const id_vec3 = b.id();
        const id_vec4 = b.id();
        const id_fn_void = b.id();
        const id_main = b.id();
        const id_label = b.id();
        const id_ptr_out = b.id();
        const id_out_var = b.id();
        const id_ptr_in = b.id();
        const id_in_var = b.id();
        const id_const_1f = b.id();

        // EntryPoint
        const entry_start = b.pos;
        b.emitInst(Op.EntryPoint, 0); b.emit(4); b.emit(id_main);
        _ = b.emitString("main");
        b.emit(id_out_var); b.emit(id_in_var);
        b.patchWordCount(entry_start, @intCast(b.pos - entry_start));

        b.emitInst(Op.ExecutionMode, 3); b.emit(id_main); b.emit(7);

        // Decorations
        b.emitInst(Op.Decorate, 4); b.emit(id_out_var); b.emit(Decoration.Location); b.emit(0);
        b.emitInst(Op.Decorate, 4); b.emit(id_in_var); b.emit(Decoration.Location); b.emit(0);

        // Types
        b.emitInst(Op.TypeVoid, 2); b.emit(id_void);
        b.emitInst(Op.TypeFloat, 3); b.emit(id_float); b.emit(32);
        b.emitInst(Op.TypeVector, 4); b.emit(id_vec3); b.emit(id_float); b.emit(3);
        b.emitInst(Op.TypeVector, 4); b.emit(id_vec4); b.emit(id_float); b.emit(4);
        b.emitInst(Op.TypeFunction, 3); b.emit(id_fn_void); b.emit(id_void);

        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_out); b.emit(StorageClass.Output); b.emit(id_vec4);
        b.emitInst(Op.Variable, 4); b.emit(id_ptr_out); b.emit(id_out_var); b.emit(StorageClass.Output);
        b.emitInst(Op.TypePointer, 4); b.emit(id_ptr_in); b.emit(StorageClass.Input); b.emit(id_vec3);
        b.emitInst(Op.Variable, 4); b.emit(id_ptr_in); b.emit(id_in_var); b.emit(StorageClass.Input);
        b.emitInst(Op.Constant, 4); b.emit(id_float); b.emit(id_const_1f); b.emitF32(1.0);

        // Function
        b.emitInst(Op.Function, 5); b.emit(id_void); b.emit(id_main); b.emit(0); b.emit(id_fn_void);
        b.emitInst(Op.Label, 2); b.emit(id_label);

        const id_col = b.id();
        b.emitInst(Op.Load, 4); b.emit(id_vec3); b.emit(id_col); b.emit(id_in_var);
        const id_cx = b.id();
        const id_cy = b.id();
        const id_cz = b.id();
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_cx); b.emit(id_col); b.emit(0);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_cy); b.emit(id_col); b.emit(1);
        b.emitInst(Op.CompositeExtract, 5); b.emit(id_float); b.emit(id_cz); b.emit(id_col); b.emit(2);
        const id_result = b.id();
        b.emitInst(Op.CompositeConstruct, 7); b.emit(id_vec4); b.emit(id_result); b.emit(id_cx); b.emit(id_cy); b.emit(id_cz); b.emit(id_const_1f);
        b.emitInst(Op.Store, 3); b.emit(id_out_var); b.emit(id_result);

        b.emitInst(Op.Return, 1);
        b.emitInst(Op.FunctionEnd, 1);

        b.words[bound_pos] = b.next_id;
        return .{ .data = b.words, .len = b.pos };
    }
}

