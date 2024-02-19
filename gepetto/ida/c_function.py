import ida_hexrays
from ida_hexrays import vdui_t
import ida_funcs
import idaapi
import idc
import re

c_func_dict = {"sub_4110DC": "printf", "sub_401020": "printf", "printf": "printf",
                   "sub_401060": "scanf_s", "sub_41129E": "scanf_s",
                   "for": "for", "while": "while", "__CheckForDebuggerJustMyCode": "__CheckForDebuggerJustMyCode"}


class CFunction:
    def __init__(self, effective_address: int, view: vdui_t):
        self.ea = effective_address
        self.view = view
        self.load_func()
        # self.name = ida_funcs.get_func_name(self.ea)
        # self.arguments_address = list(ida_hexrays.decompile_func(ida_funcs.get_func(idaapi.get_screen_ea()), None).arguments)
        # self.arguments = [arg.name for arg in self.arguments_address]
        # self.variables_address = list(ida_hexrays.decompile_func(ida_funcs.get_func(idaapi.get_screen_ea()), None).lvars)
        # self.variables = [var.name for var in self.variables_address if not var.is_arg_var]
        # body = str(ida_hexrays.decompile_func(ida_funcs.get_func(self.ea), None))
        # self.calls = self.find_function_calls_with_args()
        self.body = self.rename_known_funcs(self.body)
        self.isLeaf = False
        if len(self.calls) == 0:
            self.isLeaf = True

    def load_func(self):
        self.name = ida_funcs.get_func_name(self.ea)
        self.arguments_address = list(ida_hexrays.decompile_func(ida_funcs.get_func(idaapi.get_screen_ea()), None).arguments)
        self.arguments = [arg.name for arg in self.arguments_address]
        self.variables_address = list(ida_hexrays.decompile_func(ida_funcs.get_func(idaapi.get_screen_ea()), None).lvars)
        self.variables = [var.name for var in self.variables_address if not var.is_arg_var]
        self.body = str(ida_hexrays.decompile_func(ida_funcs.get_func(self.ea), None))
        self.calls = self.find_function_calls_with_args()

    @staticmethod
    def rename_known_funcs(body):
        """
        We update the function names locally and in IDA
        @param decompiled: decompiled code in c produced by IDA
        @return: updated decompiled code after changes of known functions
        """
        # in case of intermediary function
        body = body.replace(' __cdecl', '')

        new_code = body
        for func, name in c_func_dict.items():
            new_code = new_code.replace(func, name)
            try:
                exa_representation = func.replace('sub_', '0x')
                exa_function = int(exa_representation, 16)
                idc.set_name(exa_function, name, idc.SN_NOWARN)
            except:
                continue
        return new_code

    def find_function_calls_with_args(self):
        # Regular expression pattern to match function calls and their arguments
        pattern = r'(\b[a-zA-Z_]\w*)\s*\(([^)]*)\);'

        # Find all matches using re.findall()
        matches = re.findall(pattern, self.body)

        # Dictionary to store function calls and their arguments
        function_calls_with_args = {}

        # Iterate over matches and populate the dictionary
        for match in matches:
            function_name = match[0]
            arguments = match[1].split(',') if match[1] else []
            # Remove leading and trailing whitespaces from arguments
            arguments = [arg.strip() for arg in arguments]
            function_calls_with_args[function_name] = arguments

        return function_calls_with_args

