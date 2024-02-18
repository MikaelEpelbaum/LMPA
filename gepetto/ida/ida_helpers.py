import idc
from gepetto.ida.c_function import CFunction


c_func_dict = {"sub_4110DC": "printf", "sub_401020": "printf", "printf": "printf",
                   "sub_401060": "scanf_s", "sub_41129E": "scanf_s",
                   "for": "for", "while": "while", "__CheckForDebuggerJustMyCode": "__CheckForDebuggerJustMyCode"}

pre_defined_funcs = ["sub_401000", "sub_401010", "sub_401020", "sub_401060", "sub_401219", "sub_401221", "sub_4017CD",
                     "sub_4017D7", "sub_4017E3", "sub_401827", "sub_401833", "sub_401839", "sub_40195F", "sub_4019A1",
                     "sub_401A03", "sub_401A0B", "sub_401A37", "sub_401AE4"]


def rename_known_funcs(decompiled: str):
    """
    We update the function names locally and in IDA
    @param decompiled: decompiled code in c produced by IDA
    @return: updated decompiled code after changes of known functions
    """
    # in case of intermediary function
    decompiled = str(decompiled).replace(' __cdecl', '')

    new_code = decompiled
    for func, name in c_func_dict.items():
        new_code = new_code.replace(func, name)
        try:
            exa_representation = func.replace('sub_', '0x')
            exa_function = int(exa_representation, 16)
            idc.set_name(exa_function, name, idc.SN_NOWARN)
        except:
            continue
    return new_code


def get_filled_format(func: ):
    # func_name = "\"function name\": {{\"\"\n{func_name}\": [\" replace with function guessed name\", \"fill_confidence_level\"]\"}} ".format(func_name=params['func_name'])
    func_name = "\"function name\": {{\"\"\n{func_name}\": [\" replace with function guessed name\", \"fill_confidence_level\"]}} ".format(
        func_name=params['func_name'])

    func_args = {}
    for arg in params['func_args']:
        func_args[arg] = "[\"replace with argument guessed name\", \"fill_confidence_level\"]"
    func_vars = {}
    for var in params['local_vars']:
        func_vars[var] = "[\"replace with local variable guessed name\", \"fill_confidence_level\"]"
    func_calls = {}
    for call in params['function_calls']:
        if call in Helper.c_func_dict.keys():
            continue
        func_calls[call] = "[\"replace with called function guessed name\", \"fill_confidence_level\"]"

    unwrapped = " {}, \"function arguments\": {}, \"function variables\": {}, \"function calls\": {}".format(
        func_name, str(func_args), str(func_vars), str(func_calls))
    return "{" + unwrapped + "}"


