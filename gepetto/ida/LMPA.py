import functools
import json
import re

import idaapi
import ida_hexrays
import idc

import gepetto.config

_ = gepetto.config.translate.gettext


def chosen_function_inferer_using_LLM(chosen_func_body, called_funcs, view, response=False):
    if response:
        print("1")
        print()
        print(response)
        res = json.loads(response)
        print(res)
        # update chosen function body according to LLM response
        for func_name, func_body in called_funcs.items():
            new_func_name = Helper.get_func_name(Helper.get_called_func(func_name))
            new_function_name = [item.get('function name', {}).get(new_func_name) for item in res]
            new_function_name = [x for x in new_function_name if x is not None]
            exa_representation = func_name.replace('sub_', '0x')
            exa_function = int(exa_representation, 16)
            idc.set_name(exa_function, new_function_name[0][0], idc.SN_NOWARN)
            # update called function
        view.refresh_ctext()

        # Prepares prompt
        chosen_func_new_body = str(ida_hexrays.decompile(idaapi.get_screen_ea()))
        params = Helper.extract_c_function_details(chosen_func_new_body)
        requested_format = Helper.build_format(params)
        promt = "Can you help me guess some information for the following decompiled C function from a binary program?" \
                " The following is the decompiled C function: \n{decompiler_output}" \
                " In the above function, what are good names for \n{params}, respectively?" \
                " You must follow the format \n{format} and return a valid JSON with (use double quotes only)." \
                " DON'T INCLUDE CHANGES OF VARIABLES CONVENTIONAL NAMINGS" \
                " keep only high level confidence levels. RETURN ONLY MEANINGFUL CHANGES"

        # interact with GPT
        gepetto.config.model.query_model_async(
            _(promt).format(decompiler_output=chosen_func_new_body, params=str(list(params.keys())), format=requested_format),
            functools.partial(called_functions_inferrer, called_funcs, chosen_func_new_body, view))


    else:
        print("2")
        # Prepares prompt
        params = Helper.extract_c_function_details(chosen_func_body)
        requested_format = Helper.build_format(params)
        promt = "Can you help me guess some information for the following decompiled C function from a binary program?" \
                " The following is the decompiled C function: \n{decompiler_output}" \
                " In the above function, what are good names for \n{params}, respectively?" \
                " You must follow the format \n{format} and return a valid JSON with (use double quotes only)." \
                " DON'T INCLUDE CHANGES OF VARIABLES CONVENTIONAL NAMINGS" \
                " keep only high level confidence levels. RETURN ONLY MEANINGFUL CHANGES"

        # interact with GPT
        gepetto.config.model.query_model_async(
            _(promt).format(decompiler_output=chosen_func_body, params=str(list(params.keys())), format=requested_format),
            functools.partial(called_functions_inferrer, called_funcs, chosen_func_body, view))


def called_functions_inferrer(called_funcs: dict, chosen_func_body, view, response):
    print("3")
    res = json.loads(response)
    chosen_function_name = next(iter(res.get('function name', {})), None)
    prompts = []
    # prepares prompt
    for func_name, func_body in called_funcs.items():
        # propagation prompt
        called_with_variables = Helper.extract_function_call_variables(chosen_func_body, func_name)
        comment = "/* Called in {} with input: {} */".format(chosen_function_name, called_with_variables)

        promt = "Can you help me guess some information for the following decompiled C function from a binary program?" \
                " The following is the decompiled C function: \n{comment} \n{decompiled_func}" \
                " In the above function, what are good names for \n{params}, respectively?" \
                " You must follow the format \n{format} and return a valid JSON with (use double quotes only)." \
                " DON'T INCLUDE CHANGES OF VARIABLES CONVENTIONAL NAMINGS" \
                " keep only high level confidence levels. RETURN ONLY MEANINGFUL CHANGES"

        params = Helper.extract_c_function_details(str(func_body))
        requested_format = Helper.build_format(params)

        prompts.append(promt.format(comment=comment, decompiled_func=str(func_body), params=str(list(params.values())), format=requested_format))
    prompts = str(prompts)
    prompts = "IF THERE ARE MORE THAN ONE ANSWER THEN YOUR GLOBAL RETURNED ANSWER SHOULD BE A VALID JSON." \
              "ONLY VALID JSON ARE ACCEPTABLE" + prompts
    print(prompts)

    # interact with GPT
    gepetto.config.model.query_model_async(prompts, functools.partial(chosen_function_inferer_using_LLM, chosen_func_body, called_funcs, view))


class LMPAHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from the model and updates the
    decompiler's output.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.v = ''

    def activate(self, ctx):
        decompiler_output = str(ida_hexrays.decompile(idaapi.get_screen_ea()))
        for func, name in Helper.c_func_dict.items():
            try:
                exa_representation = func.replace('sub_', '0x')
                exa_function = int(exa_representation, 16)
                idc.set_name(exa_function, name, idc.SN_NOWARN)
            except:
                continue
        params = Helper.extract_c_function_details(decompiler_output)
        called_funcs = Helper.get_called_funcs(params)
        self.v = ida_hexrays.get_widget_vdui(ctx.widget)
        self.v.refresh_ctext()
        chosen_function_inferer_using_LLM(decompiler_output, called_funcs, self.v)

        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class Helper:
    c_func_dict = {"sub_4110DC": "printf", "sub_41129E": "scanf_s", "for": "for", "__CheckForDebuggerJustMyCode": "__CheckForDebuggerJustMyCode"}

    @staticmethod
    def intermediary_func_extract_call(decompiled: str):
        regex_pattern = r'(?<=return )(.*?)(?=\()'
        regex = re.compile(regex_pattern)
        match = regex.search(decompiled)
        return match.group().strip()

    @staticmethod
    def get_called_funcs(params):
        called_funcs = {}
        for func_name in params['function_calls']:
            if "sub_" in func_name:
                called_funcs[func_name] = Helper.get_called_func(func_name)
        return called_funcs

    @staticmethod
    def get_called_func(func_name):
        # repetitive because of the intermediary // attributes: thunk page
        exa_representation = func_name.replace('sub_', '0x')
        exa_function = int(exa_representation, 16)
        decompiled_func = str(ida_hexrays.decompile(exa_function))
        intermed = Helper.intermediary_func_extract_call(decompiled_func)
        exa_representation = intermed.replace('sub_', '0x')
        exa_function = int(exa_representation, 16)
        return str(ida_hexrays.decompile(exa_function))

    # @staticmethod
    # def get_func_name(decompiled):
    #     func_signature_pattern = re.compile(r'^\s*(?P<return_type>[A-z_][A-z0-9_]*\s*\*?)\s+(?P<name>[A-z_][A-z0-9_]*)\s*\((?P<args>.*)\)\s*{')
    #     # Match the function signature
    #     match = func_signature_pattern.match(decompiled)
    #     # Extract function details
    #     func_name = match.group('name')
    #     return func_name

    @staticmethod
    def get_func_name(c_function_declaration):
        # Regular expression pattern to match C function declaration
        pattern = r'\b(?:\w+\s+)*(\w+)\s*\([^)]*\)'

        # Match the pattern in the input string
        match = re.match(pattern, c_function_declaration)

        if match:
            return match.group(1)  # Return the first matched group (function name)
        else:
            return None  # Return None if no match found


    @staticmethod
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
            if call in Helper.c_func_dict.keys():
                continue
            func_calls[call] = "[\"replace with called function guessed name\", \"fill_confidence_level\"]"

        unwrapped = " {}, \"function arguments\": {}, \"function variables\": {}, \"function calls\": {}".format(
            func_name, str(func_args), str(func_vars), str(func_calls))
        return "{" + unwrapped + "}"

    @staticmethod
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
            Helper.c_func_dict[func_name] = 'current'
            if called_func_name in Helper.c_func_dict.keys():
                continue
            function_calls.append(called_func_name)

        returned_dic['func_name'] = func_name
        func_args = Helper.extract_function_args(c_function)
        func_args = [i for i in func_args if i != 'const']
        func_args = func_args[1::2]
        returned_dic['func_args'] = func_args
        returned_dic['local_vars'] = local_vars
        returned_dic['function_calls'] = function_calls

        return returned_dic

    @staticmethod
    def extract_function_args(c_function):
        pattern = r'\b\w+\s+\w+\s*\(\s*(.*?)\s*\)'
        match = re.search(pattern, c_function)
        if match:
            arguments_str = match.group(1)
            argument_names = re.findall(r'\b\w+\b', arguments_str)
            return argument_names
        return []

    @staticmethod
    def extract_function_call_variables(scope: str, func: str):
        vars = []
        occurrences = [i for i in range(len(scope)) if scope.startswith(func + "(", i)]
        # print(scope)
        for occurrence in occurrences:
            closing = scope[occurrence:].find(")")
            vars.append(scope[occurrence + len(func) + 1: occurrence + closing])
        return vars


    # SOMEHOW THIS METHOD STOPS IDA
    # @staticmethod
    # def extract_function_call_variables(scope: str, func: str):
    #     vars = []
    #     print("1")
    #     while scope.find(func + "("):
    #         print("2")
    #         occurrence = scope.find(func + "(")
    #         closing = scope[occurrence:].find(")")
    #         print("3")
    #         vars.append(scope[occurrence + len(func) + 1: occurrence + closing])
    #         print("4")
    #         scope = scope[closing:]
    #     return vars