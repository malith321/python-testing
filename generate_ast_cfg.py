import ast
import graphviz
from radon.complexity import cc_visit
import os # Import the os module

# --- Your Python code to analyze ---
code_to_analyze = """
def analyze_user_behavior(users):
    suspicious_users = []
    for user in users:
        if user['login_attempts'] > 5 or user['ip'] in ['192.168.1.1', '10.0.0.5']:
            if user['location'] != 'home':
                if user['last_login_time'] < '2025-07-20':
                    suspicious_users.append(user)
                elif user['account_status'] == 'suspended':
                    continue
                else:
                    if user['browser'] not in ['Chrome', 'Firefox']:
                        suspicious_users.append(user)
                    else:
                        if 'vpn' in user.get('tags', []):
                            suspicious_users.append(user)
            elif user['location'] == 'office':
                if user['access_level'] > 5:
                    if user['downloads'] > 100 and user['shared_links'] > 10:
                        suspicious_users.append(user)
        else:
            if user['account_status'] == 'active':
                if user['recent_actions']:
                    for action in user['recent_actions']:
                        if action['type'] == 'delete' and action['scope'] == 'global':
                            suspicious_users.append(user)
                        elif action['type'] == 'login' and action['success'] is False:
                            if user['alerts'] > 2:
                                suspicious_users.append(user)
    return suspicious_users
"""

class CFGVisitor(ast.NodeVisitor):
    def __init__(self, dot_graph, code_lines):
        self.dot = dot_graph
        self.node_counter = 0
        self.current_node = None
        self.branch_stack = []
        self.loop_stack = []
        self.code_lines = code_lines
        self.function_exit_node_id = None

    def new_node(self, label, shape='box', style='rounded', color='black', fillcolor=None):
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        if fillcolor:
            self.dot.node(node_id, label, shape=shape, style=style, color=color, fillcolor=fillcolor, peripheries='1', fixedsize='false')
        else:
            self.dot.node(node_id, label, shape=shape, style=style, color=color)
        return node_id

    def add_edge(self, source, target, label=''):
        self.dot.edge(source, target, label=label)

    def visit(self, node):
        old_current_node = self.current_node
        start_line = getattr(node, 'lineno', None)
        end_line = getattr(node, 'end_lineno', start_line)

        node_label_base = node.__class__.__name__

        if start_line is not None:
            effective_start_line = start_line - 1
            effective_end_line = end_line if end_line is not None else start_line

            if effective_end_line == effective_start_line + 1:
                snippet = self.code_lines[effective_start_line].strip()
            elif effective_start_line < effective_end_line and \
                 0 <= effective_start_line < len(self.code_lines) and \
                 0 <= effective_end_line <= len(self.code_lines):
                snippet = "\n".join(self.code_lines[effective_start_line : effective_end_line]).strip()
            else:
                snippet = ""

            if snippet:
                display_snippet = snippet if len(snippet) < 70 else snippet[:67] + "..."
                node_label = f"L{start_line}: {display_snippet}"
            else:
                node_label = f"L{start_line}: {node_label_base}"
        else:
            node_label = f"<{node_label_base}>"

        node_id = self.new_node(node_label)
        if self.current_node:
            self.add_edge(self.current_node, node_id)
        self.current_node = node_id
        node._id = node_id

        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        visitor(node)
        pass

    def generic_visit(self, node):
        last_visited_child_node_id = None
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        prev_current = self.current_node
                        self.current_node = node._id
                        self.visit(item)
                        if self.current_node != item._id:
                            last_visited_child_node_id = self.current_node
                        else:
                             last_visited_child_node_id = item._id
                        self.current_node = prev_current
            elif isinstance(value, ast.AST):
                prev_current = self.current_node
                self.current_node = node._id
                self.visit(value)
                if self.current_node != value._id:
                    last_visited_child_node_id = self.current_node
                else:
                    last_visited_child_node_id = value._id
                self.current_node = prev_current

        if last_visited_child_node_id and node._id and last_visited_child_node_id != node._id:
            self.current_node = last_visited_child_node_id

    def visit_FunctionDef(self, node):
        entry_node_id = self.new_node(f"ENTRY: {node.name}", shape='ellipse', color='green')
        self.current_node = entry_node_id
        self.function_exit_node_id = self.new_node(f"EXIT: {node.name}", shape='doublecircle', color='red')

        if node.args:
            try:
                args_summary = ast.unparse(node.args).strip()
            except AttributeError:
                args_summary = ", ".join([arg.arg for arg in node.args.args])

            args_node_id = self.new_node(f"ARGS: ({args_summary})", shape='rect', style='filled', fillcolor='lightgray')
            self.add_edge(self.current_node, args_node_id)
            self.current_node = args_node_id

        for stmt in node.body:
            prev_current = self.current_node
            self.visit(stmt)
            if prev_current is not None and stmt._id is not None:
                self.add_edge(prev_current, stmt._id)

        if self.current_node and self.current_node != self.function_exit_node_id:
            self.add_edge(self.current_node, self.function_exit_node_id)
        self.current_node = self.function_exit_node_id

    def visit_Return(self, node):
        return_node_id = node._id
        if self.current_node and self.current_node != return_node_id:
            self.add_edge(self.current_node, return_node_id)
        if self.function_exit_node_id:
            self.add_edge(return_node_id, self.function_exit_node_id, label='Return')
        self.current_node = None

    def visit_If(self, node):
        test_node_id = node._id
        current_after_if_test = self.current_node

        if node.body:
            self.current_node = test_node_id
            self.visit(node.body[0])
            if_body_entry_node_id = node.body[0]._id
            if_body_exit_node_id = self.current_node
            self.add_edge(test_node_id, if_body_entry_node_id, label='True')
        else:
            if_body_exit_node_id = test_node_id

        if node.orelse:
            self.current_node = test_node_id
            self.visit(node.orelse[0])
            orelse_body_entry_node_id = node.orelse[0]._id
            orelse_body_exit_node_id = self.current_node
            self.add_edge(test_node_id, orelse_body_entry_node_id, label='False')
        else:
            orelse_body_exit_node_id = test_node_id
            self.add_edge(test_node_id, orelse_body_exit_node_id, label='False (No else)')

        self.current_node = current_after_if_test

    def visit_For(self, node):
        loop_header_node_id = node._id
        current_before_loop = self.current_node

        if current_before_loop:
            self.add_edge(current_before_loop, loop_header_node_id)

        if node.body:
            self.current_node = loop_header_node_id
            self.visit(node.body[0])
            loop_body_entry_node_id = node.body[0]._id
            loop_body_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_body_entry_node_id, label='Enter Loop')
            self.add_edge(loop_body_exit_node_id, loop_header_node_id, label='Loop back')
        else:
            loop_body_exit_node_id = loop_header_node_id

        if node.orelse:
            self.current_node = loop_header_node_id
            self.visit(node.orelse[0])
            loop_else_entry_node_id = node.orelse[0]._id
            loop_else_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_else_entry_node_id, label='Else (No Break)')
        else:
            loop_else_exit_node_id = loop_header_node_id

        self.current_node = loop_header_node_id

    def visit_While(self, node):
        loop_header_node_id = node._id
        current_before_loop = self.current_node

        if current_before_loop:
            self.add_edge(current_before_loop, loop_header_node_id)

        if node.body:
            self.current_node = loop_header_node_id
            self.visit(node.body[0])
            loop_body_entry_node_id = node.body[0]._id
            loop_body_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_body_entry_node_id, label='True')
            self.add_edge(loop_body_exit_node_id, loop_header_node_id, label='Loop back')
        else:
            loop_body_exit_node_id = loop_header_node_id

        if node.orelse:
            self.current_node = loop_header_node_id
            self.visit(node.orelse[0])
            loop_else_entry_node_id = node.orelse[0]._id
            loop_else_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_else_entry_node_id, label='False (Else)')
        else:
            loop_else_exit_node_id = loop_header_node_id
            self.add_edge(loop_header_node_id, loop_else_exit_node_id, label='False')

        self.current_node = loop_header_node_id


# Main execution
if __name__ == "__main__":
    try:
        tree = ast.parse(code_to_analyze)
        code_lines = code_to_analyze.splitlines()

        # --- Calculate Cyclomatic Complexity using Radon ---
        complexity_results = cc_visit(code_to_analyze)
        print("\n--- Cyclomatic Complexity (Radon) ---")
        found_complexity = False
        for func in complexity_results:
            if func.name == "analyze_user_behavior":
                print(f"Function: {func.name}, Complexity: {func.complexity}")
                found_complexity = True
                break
        if not found_complexity:
            print("Could not find complexity for 'analyze_user_behavior' function.")


        # --- Visualize Control Flow Graph ---
        dot = graphviz.Digraph(comment='Control Flow Graph', graph_attr={'rankdir': 'LR'})
        visitor = CFGVisitor(dot, code_lines)

        function_found_cfg = False
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "analyze_user_behavior":
                visitor.visit_FunctionDef(node)
                function_found_cfg = True
                break
        
        if not function_found_cfg:
            print("Error: 'analyze_user_behavior' function not found for CFG generation.")

        # Explicitly define the output path relative to the current working directory
        output_filename = "user_behavior_cfg_ast"
        # Use os.path.join to create a platform-independent path
        dot_filepath = os.path.join(os.getcwd(), f"{output_filename}.dot")
        
        dot.render(dot_filepath, view=False, format='dot', cleanup=True)
        print(f"CFG .dot file generated: {dot_filepath}")

    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please ensure your Python code is syntactically correct and Graphviz (system-wide) is installed and in your PATH.")
        print("Also, ensure 'radon' is installed (`pip install radon`) and 'astunparse' if you are on Python < 3.9.")
