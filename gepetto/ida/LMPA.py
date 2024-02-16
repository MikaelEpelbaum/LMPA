import functools
import json
import re

import idaapi
import ida_hexrays
import idc

import gepetto.config
from gepetto.ida.Helper import Helper

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