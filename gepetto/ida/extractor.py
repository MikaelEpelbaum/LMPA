import re

c_func_dict = {"sub_4110DC": "printf", "sub_41129E": "scanf_s", "for": "for", "__CheckForDebuggerJustMyCode": "__CheckForDebuggerJustMyCode"}

def extract_function_args(c_function):
    pattern = r'\b\w+\s+\w+\s*\(\s*(.*?)\s*\)'
    match = re.search(pattern, c_function)
    if match:
        arguments_str = match.group(1)
        argument_names = re.findall(r'\b\w+\b', arguments_str)
        return argument_names
    return []


def build_format(params: dict):
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
        if call in c_func_dict.keys():
            continue
        func_calls[call] = "[\"replace with called function guessed name\", \"fill_confidence_level\"]"

    unwrapped = " {}, \"function arguments\": {}, \"function variables\": {}, \"function calls\": {}".format(
        func_name, str(func_args), str(func_vars), str(func_calls))
    return "{" + unwrapped + "}"

def extract_c_function_details(c_function):
    returned_dic = {}
    c_function = str(c_function).replace(' __cdecl', '')

    # Define regex patterns for different parts of the function
    func_signature_pattern = re.compile(r'^\s*(?P<return_type>[A-z_][A-z0-9_]*\s*\*?)\s+(?P<name>[A-z_][A-z0-9_]*)\s*\((?P<args>.*)\)\s*{')
    local_variable_pattern = re.compile(r'\b(?P<type>[A-z_][A-z0-9_]*\s*\*?)\s+(?P<var_name>[A-z_][A-z0-9_]*)\s*;')
    function_call_pattern = re.compile(r'(?P<func_name>[A-z_][A-z0-9_]*\s*)\((?P<arguments>[^()]*)\)')

    # Match the function signature
    match = func_signature_pattern.match(c_function)
    if not match:
        return None

    # Extract function details
    func_name = match.group('name')

    # Extract local variables
    local_vars = []
    for local_match in local_variable_pattern.finditer(c_function):
        local_var_name = local_match.group('var_name')
        local_vars.append(local_var_name)

    # Extract function calls
    function_calls = []
    for call_match in function_call_pattern.finditer(c_function):
        called_func_name = call_match.group('func_name').strip()
        c_func_dict[func_name] = 'current'
        if called_func_name in c_func_dict.keys():
            continue
        function_calls.append(called_func_name)

    returned_dic['func_name'] = func_name
    func_args = extract_function_args(c_function)
    func_args = [i for i in func_args if i != 'const']
    func_args = func_args[1::2]
    returned_dic['func_args'] = func_args
    returned_dic['local_vars'] = local_vars
    returned_dic['function_calls'] = function_calls

    return returned_dic


def extract_function_call_variables(scope: str, func: str):
    vars = []
    occurrences = [i for i in range(len(scope)) if scope.startswith(func + "(", i)]
    # print(scope)
    for occurrence in occurrences:
        closing = scope[occurrence:].find(")")
        vars.append(scope[occurrence + len(func) + 1: occurrence+closing])
    return vars


def intermediary_func_extract_call(decompiled: str):
    regex_pattern = r'(?<=return )(.*?)(?=\()'
    regex = re.compile(regex_pattern)
    match = regex.search(decompiled)
    return match.group().strip()

