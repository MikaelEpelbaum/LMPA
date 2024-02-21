import networkx
from gepetto.ida.c_function import CFunction

class Tree:
    def __init__(self, effective_address: int, view):
        self.G = networkx.DiGraph()
        self.G.add_node(0, data=CFunction(effective_address, view))
        self.Root = self.G.nodes()[0]
        if not self.G.nodes()[0]['data'].isLeaf:
            self.__build_tree(0)
            print(self.G)

    def __build_tree(self, i):
        for called_function, args in CFunction.find_function_calls_with_args(self.G.nodes()[i]['data'].body).items():
            if str(called_function).startswith('sub_'):
                exa_representation = called_function.replace('sub_', '0x')
                exa_function = int(exa_representation, 16)
                func = CFunction(exa_function)
                self.G.add_node(self.G.number_of_nodes()+1, data=func)
                self.G.add_edge(i, self.G.number_of_nodes())
                self.__build_tree(self.G.number_of_nodes())

