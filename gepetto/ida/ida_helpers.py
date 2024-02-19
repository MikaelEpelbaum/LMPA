from gepetto.ida.c_function import CFunction


c_func_dict = {"sub_4110DC": "printf", "sub_401020": "printf", "printf": "printf",
                   "sub_401060": "scanf_s", "sub_41129E": "scanf_s",
                   "for": "for", "while": "while", "__CheckForDebuggerJustMyCode": "__CheckForDebuggerJustMyCode"}

pre_defined_funcs = ["sub_401000", "sub_401010", "sub_401020", "sub_401060", "sub_401219", "sub_401221", "sub_4017CD",
                     "sub_4017D7", "sub_4017E3", "sub_401827", "sub_401833", "sub_401839", "sub_40195F", "sub_4019A1",
                     "sub_401A03", "sub_401A0B", "sub_401A37", "sub_401AE4"]


def get_format(func: CFunction):
    func_name = "\"function name\": {{\"\"\n{func_name}\": [\" replace with function guessed name\", \"fill_confidence_level\"]}} ".format(
        func_name=func.name)
    func_args = {}
    for arg in func.arguments:
        func_args[arg] = "[\"replace with argument guessed name\", \"fill_confidence_level\"]"
    func_vars = {}
    for var in func.variables:
        func_vars[var] = "[\"replace with local variable guessed name\", \"fill_confidence_level\"]"
    func_calls = {}
    for call in func.calls:
        func_calls[call] = "[\"replace with called function guessed name\", \"fill_confidence_level\"]"

    unwrapped = " {}, \"function arguments\": {}, \"function variables\": {}, \"function calls\": {}".format(
        func_name, str(func_args), str(func_vars), str(func_calls))
    return "{" + unwrapped + "}"


