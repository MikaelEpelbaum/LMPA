import json
import idaapi
import ida_hexrays
import idc

import gepetto.config
from gepetto.ida.Prompts import chosen_func_prompt, comment_prompt
from gepetto.ida.ida_helpers import get_format

_ = gepetto.config.translate.gettext


def apply_changes(c_func, LLM_result, node_id):
    response = json.loads(LLM_result)
    # print(LLM_result)

    # rename function
    original_func_name, guessed_func_name = next(iter(response['function name'].items()))
    exa_function = int(hex(c_func.ea), 16)
    guessed_func_name = guessed_func_name[0]
    idc.set_name(exa_function, guessed_func_name, idc.SN_NOWARN)
    print(c_func.ea)
    print(exa_function, guessed_func_name)

    # update args and vars names
    args_iterator = iter(response['function arguments'].items())
    for arg in args_iterator:
        original_arg_name, guessed_arg_name = arg
        x = ida_hexrays.rename_lvar(exa_function, original_arg_name, guessed_arg_name[0])
        print(x)
    vars_iterator = iter(response['function variables'].items())
    for var in vars_iterator:
        original_var_name, guessed_var_name = var
        ida_hexrays.rename_lvar(exa_function, original_var_name, guessed_var_name[0])

    # update called funcs
    for called, guessed_call_name in response['function calls'].items():
        try:
            exa_representation = called.replace('sub_', '0x')
            exa_function = int(exa_representation, 16)
            idc.set_name(exa_function, guessed_call_name[0], idc.SN_NOWARN)
        except:
            print("problems with called functions")
            pass
    c_func.load_func()


from gepetto.ida.Tree import Tree
class LMPAHandler(idaapi.action_handler_t):
    """
    This handler requests new variable names from the model and updates the
    decompiler's output.
    """

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        self.Tree = Tree(idaapi.get_screen_ea(), ida_hexrays.get_widget_vdui(ctx.widget))
        print(idaapi.get_screen_ea())
        self.recover_function_name_args_iteratively(2)
        return 1

    def recover_function_name_args_iteratively(self, iterations: int):
        Root = self.Tree.G.nodes()[0]['data']
        # print(Root)
        if Root.isLeaf:
            # print("LEAF")
            params = [Root.name] + Root.arguments + Root.variables
            # interact with GPT
            response = gepetto.config.model.query_model_sync(
                _(chosen_func_prompt).format(decompiler_output=Root.body, params=params, format=(get_format(Root))))
            # parse response and update changes apply to itself
            apply_changes(Root, response, 0)
            Root.view.refresh_view(True)

        else:
            node_id = 0
            # print("TREE")
            # need to update stopping condition, gradient descent like (till convergence)
            while (iterations >= 0):
                # main function from which everything starts
                params = [Root.name] + Root.arguments + Root.variables
                # interact with GPT
                response = gepetto.config.model.query_model_sync(
                    _(chosen_func_prompt).format(decompiler_output=Root.body, params=params, format=(get_format(Root))))
                # parse response and update changes apply to itself
                apply_changes(Root, response, node_id)
                Root.view.refresh_view(True)

                # sub called functions
                for edge in self.Tree.G.edges(node_id):
                    # we have irrelevant nodes because of IDA's decompilation operation so we "jump" over them
                    relevent_node_id = self.Tree.G.out_edges(edge[1])
                    called_func_node = self.Tree.G.nodes[list(relevent_node_id)[0][1]]['data']
                    params = [called_func_node.name] + called_func_node.arguments + called_func_node.variables
                    prompt = _(chosen_func_prompt).format(decompiler_output=called_func_node.body, params=params, format=(get_format(called_func_node)))
                    comment = comment_prompt.format(function_name=Root.name, variables=Root.arguments)
                    # interact with GPT
                    response = gepetto.config.model.query_model_sync(comment + prompt)
                    # parse response and update changes apply to itself and to caller func
                    apply_changes(called_func_node, response, node_id)

                iterations -= 1


    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS