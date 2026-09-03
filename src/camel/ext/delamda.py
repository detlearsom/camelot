"""Rewrite lambda expressions into CaMeL-compatible equivalents.

The CaMeL interpreter does not support lambda functions. This module
eliminates the most common patterns before verification and interpretation:

    min(items, key=lambda x: expr)    → explicit min loop
    max(items, key=lambda x: expr)    → explicit max loop
    sorted(items, key=lambda x: expr) → decorated-sort comprehension
    map(lambda x: expr, items)        → list comprehension
    filter(lambda x: pred, items)     → list comprehension
"""

import ast
import copy


def _rename(node: ast.expr, old: str, new: str) -> ast.expr:
    class _R(ast.NodeTransformer):
        def visit_Name(self, n: ast.Name) -> ast.Name:
            return ast.Name(id=new, ctx=n.ctx) if n.id == old else n
    return _R().visit(copy.deepcopy(node))


def _assign(name: str, value: ast.expr) -> ast.Assign:
    return ast.fix_missing_locations(
        ast.Assign(targets=[ast.Name(id=name, ctx=ast.Store())], value=value)
    )


def _comp(elt: ast.expr, target: str, iter_: ast.expr, ifs: list) -> ast.ListComp:
    return ast.ListComp(
        elt=elt,
        generators=[ast.comprehension(
            target=ast.Name(id=target, ctx=ast.Store()),
            iter=iter_,
            ifs=ifs,
            is_async=0,
        )],
    )


class _Extractor(ast.NodeTransformer):
    """Replace lambda-using calls with temp vars; collect pre-statements."""

    def __init__(self):
        self._n = 0
        self.pre: list[ast.stmt] = []

    def _fresh(self) -> int:
        i = self._n
        self._n += 1
        return i

    def visit_Call(self, node: ast.Call) -> ast.expr:
        self.generic_visit(node)  # process children first

        if not isinstance(node.func, ast.Name):
            return node
        fn = node.func.id

        if fn in ('min', 'max') and node.args:
            key_kw = next(
                (kw for kw in node.keywords
                 if kw.arg == 'key' and isinstance(kw.value, ast.Lambda)),
                None,
            )
            if key_kw and len(key_kw.value.args.args) == 1:
                return self._minmax(fn, node.args[0], key_kw.value)

        if fn == 'sorted' and node.args:
            key_kw = next(
                (kw for kw in node.keywords
                 if kw.arg == 'key' and isinstance(kw.value, ast.Lambda)),
                None,
            )
            if key_kw and len(key_kw.value.args.args) == 1:
                other_kws = [kw for kw in node.keywords if kw.arg != 'key']
                return self._sorted(node.args[0], key_kw.value, other_kws)

        if fn == 'map' and len(node.args) == 2 and isinstance(node.args[0], ast.Lambda):
            lam = node.args[0]
            if len(lam.args.args) == 1:
                return self._map(lam, node.args[1])

        if fn == 'filter' and len(node.args) == 2 and isinstance(node.args[0], ast.Lambda):
            lam = node.args[0]
            if len(lam.args.args) == 1:
                return self._filter(lam, node.args[1])

        return node

    def _minmax(self, fn: str, iterable: ast.expr, lam: ast.Lambda) -> ast.expr:
        i = self._fresh()
        lv = lam.args.args[0].arg
        item_v   = f'_camel_item_{i}'
        curkey_v = f'_camel_curkey_{i}'
        bestkey_v = f'_camel_bestkey_{i}'
        result_v = f'_camel_result_{i}'
        key_expr = _rename(lam.body, lv, item_v)
        cmp_op = ast.Lt() if fn == 'min' else ast.Gt()

        loop = ast.For(
            target=ast.Name(id=item_v, ctx=ast.Store()),
            iter=iterable,
            body=[
                _assign(curkey_v, key_expr),
                ast.If(
                    test=ast.BoolOp(op=ast.Or(), values=[
                        ast.Compare(
                            left=ast.Name(id=bestkey_v, ctx=ast.Load()),
                            ops=[ast.Is()],
                            comparators=[ast.Constant(value=None)],
                        ),
                        ast.Compare(
                            left=ast.Name(id=curkey_v, ctx=ast.Load()),
                            ops=[cmp_op],
                            comparators=[ast.Name(id=bestkey_v, ctx=ast.Load())],
                        ),
                    ]),
                    body=[
                        _assign(bestkey_v, ast.Name(id=curkey_v, ctx=ast.Load())),
                        _assign(result_v, ast.Name(id=item_v, ctx=ast.Load())),
                    ],
                    orelse=[],
                ),
            ],
            orelse=[],
        )
        self.pre += [
            _assign(result_v, ast.Constant(value=None)),
            _assign(bestkey_v, ast.Constant(value=None)),
            ast.fix_missing_locations(loop),
        ]
        return ast.Name(id=result_v, ctx=ast.Load())

    def _sorted(
        self,
        iterable: ast.expr,
        lam: ast.Lambda,
        other_kws: list,
    ) -> ast.expr:
        i = self._fresh()
        lv = lam.args.args[0].arg
        item_v   = f'_camel_item_{i}'
        pairs_v  = f'_camel_pairs_{i}'
        si_v     = f'_camel_si_{i}'
        result_v = f'_camel_result_{i}'
        key_expr = _rename(lam.body, lv, item_v)

        pairs_comp = _comp(
            elt=ast.Tuple(
                elts=[key_expr, ast.Name(id=item_v, ctx=ast.Load())],
                ctx=ast.Load(),
            ),
            target=item_v,
            iter_=iterable,
            ifs=[],
        )
        sorted_call = ast.Call(
            func=ast.Name(id='sorted', ctx=ast.Load()),
            args=[ast.Name(id=pairs_v, ctx=ast.Load())],
            keywords=other_kws,
        )
        result_comp = ast.ListComp(
            elt=ast.Name(id=si_v, ctx=ast.Load()),
            generators=[ast.comprehension(
                target=ast.Tuple(
                    elts=[ast.Name(id='_', ctx=ast.Store()),
                          ast.Name(id=si_v, ctx=ast.Store())],
                    ctx=ast.Store(),
                ),
                iter=sorted_call,
                ifs=[],
                is_async=0,
            )],
        )
        self.pre += [
            ast.fix_missing_locations(_assign(pairs_v, pairs_comp)),
            ast.fix_missing_locations(_assign(result_v, result_comp)),
        ]
        return ast.Name(id=result_v, ctx=ast.Load())

    def _map(self, lam: ast.Lambda, iterable: ast.expr) -> ast.expr:
        i = self._fresh()
        lv = lam.args.args[0].arg
        item_v   = f'_camel_item_{i}'
        result_v = f'_camel_result_{i}'
        self.pre.append(ast.fix_missing_locations(
            _assign(result_v, _comp(_rename(lam.body, lv, item_v), item_v, iterable, []))
        ))
        return ast.Name(id=result_v, ctx=ast.Load())

    def _filter(self, lam: ast.Lambda, iterable: ast.expr) -> ast.expr:
        i = self._fresh()
        lv = lam.args.args[0].arg
        item_v   = f'_camel_item_{i}'
        result_v = f'_camel_result_{i}'
        pred = _rename(lam.body, lv, item_v)
        self.pre.append(ast.fix_missing_locations(
            _assign(result_v, _comp(ast.Name(id=item_v, ctx=ast.Load()), item_v, iterable, [pred]))
        ))
        return ast.Name(id=result_v, ctx=ast.Load())


def _transform_stmts(stmts: list[ast.stmt]) -> list[ast.stmt]:
    out: list[ast.stmt] = []
    for stmt in stmts:
        ext = _Extractor()
        new_stmt = ext.visit(stmt)
        ast.fix_missing_locations(new_stmt)
        out.extend(ext.pre)
        out.append(new_stmt)
        # Recurse into nested statement blocks
        for field, value in ast.iter_fields(new_stmt):
            if isinstance(value, list) and value and isinstance(value[0], ast.stmt):
                setattr(new_stmt, field, _transform_stmts(value))
        if isinstance(new_stmt, ast.Try):
            for handler in new_stmt.handlers:
                handler.body = _transform_stmts(handler.body)
    return out


def delamda(code: str) -> str:
    """Rewrite lambda expressions into CaMeL-compatible alternatives.

    Returns the code unchanged if it contains no lambdas or cannot be parsed.
    """
    if 'lambda' not in code:
        return code
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code

    tree.body = _transform_stmts(tree.body)
    ast.fix_missing_locations(tree)
    try:
        return ast.unparse(tree)
    except Exception:
        return code
