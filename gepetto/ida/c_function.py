import ida_hexrays
from ida_hexrays import vdui_t
import ida_funcs
import idaapi
import idautils
import re
from gepetto.ida.ida_helpers import c_func_dict, rename_known_funcs


class CFunction:
    def __init__(self, effective_address: int, view: vdui_t):
        self.ea = effective_address
        self.view = view
        self.name = ida_funcs.get_func_name(self.ea)
        self.arguments_address = list(ida_hexrays.decompile_func(ida_funcs.get_func(idaapi.get_screen_ea()), None).arguments)
        self.arguments = [arg.name for arg in self.arguments_address]
        self.variables_address = list(ida_hexrays.decompile_func(ida_funcs.get_func(idaapi.get_screen_ea()), None).lvars)
        self.variables = [var.name for var in self.variables_address if not var.is_arg_var]
        body = str(ida_hexrays.decompile_func(ida_funcs.get_func(effective_address), None))
        self.body = rename_known_funcs(body)
        self.calls = self.get_function_calls()
        self.isLeaf = False
        if len(self.calls) == 0:
            self.isLeaf = True

    def get_function_calls(self):
        pattern = r'\b([a-zA-Z_]\w*)\s*\([^)]*\);'
        all_calls = re.findall(pattern, self.body)
        function_calls = set(all_calls) - set(c_func_dict.keys())
        return function_calls



