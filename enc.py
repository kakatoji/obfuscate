#!/usr/bin/env python3
"""
pyobf_hard (final fixed)
Obfuscator Python tanpa dependensi eksternal

fitur:
- Rename identifier via AST
- Enkripsi string literal (XOR + Base85)
- Noise / opaque predicate ringan
- Packer marshal+zlib+base85 multilayer
"""

from __future__ import annotations
import ast
import argparse
import base64
import builtins
import hashlib
import keyword
import os
import random
import string
import sys
import zlib
import marshal

# --------------------- util ----------------------
SAFE_BUILTINS = set(dir(builtins)) | set(keyword.kwlist)
SAFE_PREFIXES = ("__",)
_rand = random.SystemRandom()

def _gen_name(n: int = 8) -> str:
    return "_" + "".join(_rand.choice(string.ascii_letters + string.digits) for _ in range(n))

# --------------------- set parent ----------------
def set_parents(node, parent=None):
    for child in ast.iter_child_nodes(node):
        child.parent = node
        set_parents(child, child)

# --------------------- renamer -------------------
class Renamer(ast.NodeTransformer):
    def __init__(self):
        self.map = {}

    def _should_rename(self, name: str) -> bool:
        if not name:
            return False
        if name in SAFE_BUILTINS:
            return False
        if name.startswith(SAFE_PREFIXES):
            return False
        return True

    def _new(self, old: str) -> str:
        if old not in self.map:
            self.map[old] = _gen_name(_rand.randint(6, 12))
        return self.map[old]

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        if self._should_rename(node.name):
            node.name = self._new(node.name)
        for arg in node.args.args + node.args.kwonlyargs:
            if self._should_rename(arg.arg):
                arg.arg = self._new(arg.arg)
        if node.args.vararg and self._should_rename(node.args.vararg.arg):
            node.args.vararg.arg = self._new(node.args.vararg.arg)
        if node.args.kwarg and self._should_rename(node.args.kwarg.arg):
            node.args.kwarg.arg = self._new(node.args.kwarg.arg)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.generic_visit(node)
        if self._should_rename(node.name):
            node.name = self._new(node.name)
        return node

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Load, ast.Del)) and self._should_rename(node.id):
            node.id = self._new(node.id)
        return node

    def visit_arg(self, node):
        if self._should_rename(node.arg):
            node.arg = self._new(node.arg)
        return node

# --------------------- string encryptor ----------
class StringEncryptor(ast.NodeTransformer):
    def __init__(self, key_bytes: bytes):
        self.key = key_bytes

    @staticmethod
    def _xor(data: bytes, key: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ key[i % len(key)]
        return bytes(out)

    def _enc(self, s: str) -> str:
        return base64.b85encode(self._xor(s.encode("utf-8"), self.key)).decode("ascii")

    def visit_Constant(self, node: ast.Constant):
        # jangan ubah string dalam f-string
        if isinstance(node.value, str) and not isinstance(getattr(node, "parent", None), ast.JoinedStr):
            enc = self._enc(node.value)
            dec_call = ast.Call(
                func=ast.Name(id="_pyobf_dec", ctx=ast.Load()),
                args=[ast.Constant(value=enc)],
                keywords=[]
            )
            return ast.copy_location(dec_call, node)
        return node

# --------------------- noise ---------------------
class NoiseInjector(ast.NodeTransformer):
    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        bogus_if = ast.If(
            test=ast.Compare(
                left=ast.BinOp(left=ast.Constant(value=1234567), op=ast.BitXor(), right=ast.Constant(value=1234567)),
                ops=[ast.NotEq()],
                comparators=[ast.Constant(value=0)]
            ),
            body=[ast.Pass()],
            orelse=[]
        )
        node.body.insert(0, bogus_if)
        return node

    def visit_Module(self, node):
        self.generic_visit(node)
        noise = ast.Try(
            body=[ast.Expr(value=ast.Constant(value=None))],
            handlers=[ast.ExceptHandler(type=ast.Name(id='Exception', ctx=ast.Load()), name=None, body=[ast.Pass()])],
            orelse=[],
            finalbody=[]
        )
        node.body.insert(0, noise)
        return node

# --------------------- template ------------------
PROLOGUE_TMPL = r'''
# === pyobf runtime ===
import base64,sys
def _pyobf_k():
    s = {KBYTES!r}
    try:
        mix = (len(__file__) if '__file__' in globals() else 13) ^ len(sys.version)
        return bytes((b ^ (mix & 0xFF)) for b in s)
    except Exception:
        return s
def _pyobf_dec(b85s: str) -> str:
    raw = base64.b85decode(b85s.encode('ascii'))
    k = _pyobf_k()
    out = bytearray(len(raw))
    for i,c in enumerate(raw):
        out[i] = c ^ k[i % len(k)]
    return out.decode('utf-8', errors='ignore')
'''

STUB_TMPL = r'''# -*- coding: utf-8 -*-
import sys,types,base64,zlib,marshal,hashlib,os
def _g():
    if hasattr(sys, 'gettrace') and sys.gettrace():
        raise SystemExit(0)
_g()
_D = {DATA!r}
_H = {HASH!r}
if hashlib.sha256(base64.b85decode(_D)).hexdigest() != _H:
    raise SystemExit(0)
_C = marshal.loads(zlib.decompress(base64.b85decode(_D)))
_M = types.ModuleType(__name__)
_M.__dict__['__builtins__'] = __builtins__
exec(_C, _M.__dict__)
'''

# --------------------- main ----------------------
def obfuscate_source(src: str, *, rename: bool, encrypt_strings: bool, add_noise: bool, key: bytes) -> str:
    tree = ast.parse(src)
    set_parents(tree)
    if rename:
        tree = Renamer().visit(tree)
    if add_noise:
        tree = NoiseInjector().visit(tree)
    if encrypt_strings:
        tree = StringEncryptor(key).visit(tree)
    ast.fix_missing_locations(tree)
    prologue = PROLOGUE_TMPL.format(KBYTES=key)
    return prologue + "\n" + ast.unparse(tree)

def pack_source_to_stub(src: str) -> str:
    code = compile(src, filename="<obf>", mode="exec")
    blob = marshal.dumps(code)
    comp = zlib.compress(blob, 9)
    h = hashlib.sha256(comp).hexdigest()
    b85 = base64.b85encode(comp).decode("ascii")
    return STUB_TMPL.format(DATA=b85, HASH=h)

def multilayer_pack(src: str, layers: int) -> str:
    out = src
    for _ in range(max(0, layers)):
        out = pack_source_to_stub(out)
    return out

def main():
    ap = argparse.ArgumentParser(description="Python obfuscator")
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default=None)
    ap.add_argument("--rename", action="store_true")
    ap.add_argument("--strings", action="store_true")
    ap.add_argument("--noise", action="store_true")
    ap.add_argument("--pack-layers", type=int, default=1)
    args = ap.parse_args()

    src = open(args.input, "r", encoding="utf-8").read()
    key = os.urandom(16)

    transformed = obfuscate_source(src,
                                   rename=args.rename,
                                   encrypt_strings=args.strings,
                                   add_noise=args.noise,
                                   key=key)
    packed = multilayer_pack(transformed, args.pack_layers)

    out = args.output or args.input + ".obf.py"
    with open(out, "w", encoding="utf-8") as f:
        f.write(packed)

    print(f"[+] Obfuscated -> {out}")
    print(f"    rename={args.rename}, strings={args.strings}, noise={args.noise}, layers={args.pack_layers}")

if __name__ == "__main__":
    main()
