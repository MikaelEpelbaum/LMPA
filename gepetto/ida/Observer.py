import ida_hexrays
from gepetto.ida.extractor import intermediary_func_extract_call, extract_c_function_details, build_format, extract_function_call_variables
import gepetto.config
import functools
# from gepetto.ida.handlers import LMPA

# The called functions in the func we upgrade
class Observer:
    def update(self, caller_name, original_decompiled, updated_decompiled):
        pass


# The event listener settings
class Subject:
    def __init__(self):
        self.observers = []

    def register_observer(self, observer):
        self.observers.append(observer)

    def notify_observers(self, function_name, original_decompiled, updated_decompiled):
        for observer in self.observers:
            observer.update(function_name, original_decompiled, updated_decompiled)


class Publisher(Subject):
    def publish(self, function_name, original_decompiled, updated_decompiled):
        # print("Publishing...")
        self.notify_observers(function_name, original_decompiled, updated_decompiled)


class Subscriber(Observer):
    def __init__(self, func_name):
        self.func_name = func_name

    @staticmethod
    def get_called_func(func_name):
        # repetitive because of the intermediary // attributes: thunk page
        exa_representation = func_name.replace('sub_', '0x')
        exa_function = int(exa_representation, 16)
        decompiled_func = str(ida_hexrays.decompile(exa_function))
        intermed = intermediary_func_extract_call(decompiled_func)
        exa_representation = intermed.replace('sub_', '0x')
        exa_function = int(exa_representation, 16)
        return str(ida_hexrays.decompile(exa_function))


    def update(self, caller_name, original_decompiled, updated_decompiled):
        decompiled_func = self.get_called_func(self.func_name)

        # propagation prompt
        called_with_variables = extract_function_call_variables(original_decompiled, self.func_name)
        comment = "/* Called in {} with input: {} */".format(caller_name, called_with_variables)

        promt = "Can you help me guess some information for the following decompiled C function from a binary program?" \
                " The following is the decompiled C function: \n{comment} \n{decompiled_func}" \
                " In the above function, what are good names for \n{params}, respectively?" \
                " You must follow the format \n{format} and return a valid JSON with (use double quotes only)." \
                " DON'T INCLUDE CHANGES OF VARIABLES CONVENTIONAL NAMINGS" \
                " keep only high level confidence levels. RETURN ONLY MEANINGFUL CHANGES"

        params = extract_c_function_details(str(decompiled_func))
        # del params['function_calls']
        requested_format = build_format(params)

        # print(params)

        print(promt.format(comment=comment, decompiled_func=str(decompiled_func), params=str(list(params.keys())), format=requested_format))

        # # interact with GPT
        # gepetto.config.model.query_model_async(
        #     _(promt).format(comment=comment, decompiled_func=str(decompiled_func), params=str(list(params.keys())), format=requested_format),
        #     functools.partial(LMPA, str(decompiled_func), address=idaapi.get_screen_ea(), publisher=publisher, view=v))




# # Usage
# publisher = Publisher()
# subscriber1 = Subscriber()
# subscriber2 = Subscriber()
#
# publisher.register_observer(subscriber1)
# publisher.register_observer(subscriber2)
#
# publisher.publish()
