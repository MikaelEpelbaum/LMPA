import functools
import json

import idaapi
import ida_hexrays
import idc

import gepetto.config
from gepetto.ida.Helper import Helper

_ = gepetto.config.translate.gettext


def chosen_function_inferer_using_LLM(chosen_func_body, called_funcs, view, c=4, response=False):
    if c <= 0:
        return
    # triggered by a response to an MLL query
    if response:
        print("1")
        print(response)
        res = json.loads(response)
        # update chosen function body according to LLM response
        for func_name, func_body in called_funcs.items():
            called_func = Helper.get_called_func(func_name)
            new_func_name = Helper.get_func_name(called_func)
            new_function_name = [item.get('function name', {}).get(new_func_name) for item in res]
            new_function_name = [x for x in new_function_name if x is not None]
            exa_representation = func_name.replace('sub_', '0x')
            exa_function = int(exa_representation, 16)
            idc.set_name(exa_function, new_function_name[0][0], idc.SN_NOWARN)
            # update called function
        view.refresh_ctext()

        # update chosen function callees according to LLM response
        # update func name
        for func_res in res:
            original_func_name, guessed_func_name = next(iter(func_res['function name'].items()))
            exa_representation = original_func_name.replace('sub_', '0x')
            exa_function = int(exa_representation, 16)
            guessed_func_name = guessed_func_name[0]
            idc.set_name(exa_function, guessed_func_name, idc.SN_NOWARN)
            # update args and vars names
            args_iterator = iter(func_res['function arguments'].items())
            for arg in args_iterator:
                original_arg_name, guessed_arg_name = arg
                ida_hexrays.rename_lvar(exa_function, original_arg_name, guessed_arg_name[0])
            vars_iterator = iter(func_res['function variables'].items())
            for var in vars_iterator:
                original_var_name, guessed_var_name = var
                ida_hexrays.rename_lvar(exa_function, original_var_name, guessed_var_name[0])



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
            functools.partial(called_functions_inferrer, called_funcs, chosen_func_new_body, view, c-1))


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

        # in case the func stands alone and has no calls.
        if not bool(called_funcs):
            print("3")
            # interact with GPT
            response = gepetto.config.model.query_model_sync(
                _(promt).format(decompiler_output=chosen_func_body, params=str(list(params.keys())), format=requested_format))
            res = json.loads(response)
            print(response)
            # update func name
            original_func_name, guessed_func_name = next(iter(res['function name'].items()))
            original_func_name = idaapi.get_screen_ea()
            guessed_func_name = guessed_func_name[0]
            idc.set_name(original_func_name, guessed_func_name, idc.SN_NOWARN)
            # update args and vars names
            args_iterator = iter(res['function arguments'].items())
            for arg in args_iterator:
                original_arg_name, guessed_arg_name = arg
                ida_hexrays.rename_lvar(original_func_name, original_arg_name, guessed_arg_name[0])
            vars_iterator = iter(res['function variables'].items())
            current_func_name = idaapi.get_func(idaapi.get_screen_ea()).start_ea
            # TODO: make it work with all the vars not only one bug in ida?
            for var in vars_iterator:
                original_var_name, guessed_var_name = var
                ida_hexrays.rename_lvar(original_func_name, original_var_name, guessed_var_name[0])
            # vars = []
            # for var in vars_iterator:
            #     original_var_name, guessed_var_name = var
            #     vars.append((original_var_name, guessed_var_name[0]))
            #     print(vars)
            # ida_hexrays.user_lvar_modifier_t(original_func_name, vars)

            view.refresh_ctext()

        else:
            print("4")
            # first attempt and doesn't stand alone
            # interact with GPT
            gepetto.config.model.query_model_async(
                _(promt).format(decompiler_output=chosen_func_body, params=str(list(params.keys())), format=requested_format),
                functools.partial(called_functions_inferrer, called_funcs, chosen_func_body, view, c-1))


def called_functions_inferrer(called_funcs: dict, chosen_func_body, view, c, response):
    if c <= 0:
        return
    print('5')
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
              " ONLY VALID JSON ARE ACCEPTABLE" + prompts
    print(prompts)

    # interact with GPT
    gepetto.config.model.query_model_async(prompts, functools.partial(chosen_function_inferer_using_LLM, chosen_func_body, called_funcs, view, c-1))


# import ida_helpers
from gepetto.ida.c_function import CFunction
from gepetto.ida.Prompts import chosen_func_prompt
from gepetto.ida.ida_helpers import get_format


def recover_function_name_args_iteratively(c_func: CFunction, iterations: int):
    if c_func.isLeaf:
        params = [c_func.name] + c_func.arguments + c_func.variables
        # interact with GPT
        response = gepetto.config.model.query_model_sync(
            _(chosen_func_prompt).format(decompiler_output=c_func.body, params=params, format=(get_format(c_func))))
    #     parse response and update changes
    else:
        # need to update stopping condition, gradient descent like (till convergence)
        initial_flag = True
        while(iterations >= 0):
            if initial_flag:
                params = [c_func.name] + c_func.arguments + c_func.variables
                # interact with GPT
                response = gepetto.config.model.query_model_sync(
                    _(chosen_func_prompt).format(decompiler_output=c_func.body, params=params, format=(get_format(c_func))))
            else:
                
                params = [c_func.name] + c_func.arguments + c_func.variables
                # interact with GPT
                response = gepetto.config.model.query_model_sync(
                    _(chosen_func_prompt).format(decompiler_output=c_func.body, params=params, format=(get_format(c_func))))



            iterations-=1



class LMPAHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from the model and updates the
    decompiler's output.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.v = ''

    def activate(self, ctx):
        self.view = ida_hexrays.get_widget_vdui(ctx.widget)
        c_func = CFunction(idaapi.get_screen_ea(), self.view)
        recover_function_name_args_iteratively(c_func, 4)
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


# # original
# class LMPAHandler(idaapi.action_handler_t):
#     """
#     This handler requests new variable names from the model and updates the
#     decompiler's output.
#     """
#
#     def __init__(self):
#         idaapi.action_handler_t.__init__(self)
#         self.v = ''
#
#     def activate(self, ctx):
#         decompiler_output = str(ida_hexrays.decompile(idaapi.get_screen_ea()))
#         decompiler_output = Helper.replace_known_funcs(decompiler_output)
#         # renames known functions like printf, scanf etc'
#         for func, name in Helper.c_func_dict.items():
#             try:
#                 exa_representation = func.replace('sub_', '0x')
#                 exa_function = int(exa_representation, 16)
#                 idc.set_name(exa_function, name, idc.SN_NOWARN)
#             except:
#                 continue
#
#         params = Helper.extract_c_function_details(decompiler_output)
#         called_funcs = Helper.get_called_funcs(params)
#         self.v = ida_hexrays.get_widget_vdui(ctx.widget)
#         chosen_function_inferer_using_LLM(decompiler_output, called_funcs, self.v, 4)
#
#         return 1
#
#     # This action is always available.
#     def update(self, ctx):
#         return idaapi.AST_ENABLE_ALWAYS