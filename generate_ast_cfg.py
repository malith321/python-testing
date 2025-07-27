import ast
import graphviz

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
        self.branch_stack = [] # To handle if/else/for/while branches
        self.loop_stack = []   # To handle break/continue
        self.code_lines = code_lines
        self.function_exit_node_id = None # To connect returns to

    def new_node(self, label, shape='box', style='rounded', color='black', fillcolor=None):
        node_id = f"node_{self.node_counter}"
        self.node_counter += 1
        # Pass fillcolor and other attributes only if fillcolor is provided
        if fillcolor:
            self.dot.node(node_id, label, shape=shape, style=style, color=color, fillcolor=fillcolor, peripheries='1', fixedsize='false')
        else:
            self.dot.node(node_id, label, shape=shape, style=style, color=color)
        return node_id

    def add_edge(self, source, target, label=''):
        self.dot.edge(source, target, label=label)

    def visit(self, node):
        # Store previous current_node to restore after visiting children
        old_current_node = self.current_node

        # --- Generate Node Label ---
        start_line = getattr(node, 'lineno', None)
        end_line = getattr(node, 'end_lineno', start_line) # end_lineno in Python 3.8+

        node_label_base = node.__class__.__name__ # Default base label

        if start_line is not None:
            # Adjust for 0-based list indexing and 1-based lineno
            effective_start_line = start_line - 1
            # end_lineno is line AFTER the last line of the node, so it's directly usable as slice end
            effective_end_line = end_line if end_line is not None else start_line

            # Handle cases where node might be on a single line but end_lineno is same as lineno
            if effective_end_line == effective_start_line + 1:
                # Single line statement
                snippet = self.code_lines[effective_start_line].strip()
            elif effective_start_line < effective_end_line and \
                 0 <= effective_start_line < len(self.code_lines) and \
                 0 <= effective_end_line <= len(self.code_lines): # end_line can be len(lines)
                # Multi-line statement
                snippet = "\n".join(self.code_lines[effective_start_line : effective_end_line]).strip()
            else:
                # Fallback for unexpected line numbers
                snippet = ""

            if snippet:
                # Limit snippet length for readability
                display_snippet = snippet if len(snippet) < 70 else snippet[:67] + "..."
                node_label = f"L{start_line}: {display_snippet}"
            else:
                node_label = f"L{start_line}: {node_label_base}"
        else:
            # For nodes without lineno (like ast.arguments, ast.Load, ast.Store)
            node_label = f"<{node_label_base}>"

        # --- Create and Connect Node ---
        node_id = self.new_node(node_label)
        if self.current_node:
            self.add_edge(self.current_node, node_id)
        self.current_node = node_id

        # Store the node ID on the node itself for easier linking during traversal
        # This is a common pattern in AST visitors for graph building
        node._id = node_id

        # --- Visit Children ---
        method = 'visit_' + node.__class__.__name__
        visitor = getattr(self, method, self.generic_visit)
        visitor(node)

        pass # This 'pass' ensures the visit method has a block if no other logic changes 'current_node'

    def generic_visit(self, node):
        """
        Generic visit method, traverses children.
        Ensures sequential flow by linking child's last node to parent's current node.
        """
        last_visited_child_node_id = None
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        prev_current = self.current_node # Save current before child visit
                        self.current_node = node._id # Set parent node as current for child's entry
                        self.visit(item)
                        if self.current_node != item._id: # If child visitor changed current, this is new end
                            last_visited_child_node_id = self.current_node
                        else:
                             last_visited_child_node_id = item._id # Use child's ID if no change
                        self.current_node = prev_current # Restore parent's current for next child
            elif isinstance(value, ast.AST):
                prev_current = self.current_node
                self.current_node = node._id # Set parent node as current for child's entry
                self.visit(value)
                if self.current_node != value._id:
                    last_visited_child_node_id = self.current_node
                else:
                    last_visited_child_node_id = value._id
                self.current_node = prev_current

        # After visiting all children, if there were children, link the parent node to the last child's end.
        # This creates the sequential flow within a block.
        if last_visited_child_node_id and node._id and last_visited_child_node_id != node._id:
            # We already added an edge from old_current_node to node._id in visit().
            # Now, ensure node._id connects to its first child, and the last child connects back to the parent's
            # 'conceptual' flow after the node. This is where a proper CFG block concept is needed.
            # For this simple visitor, we'll just ensure the current_node is updated to the last node in sequence.
            self.current_node = last_visited_child_node_id


    # Specific visitors for control flow structures
    def visit_FunctionDef(self, node):
        entry_node_id = self.new_node(f"ENTRY: {node.name}", shape='ellipse', color='green')
        self.current_node = entry_node_id
        # Set a global exit node for the function
        self.function_exit_node_id = self.new_node(f"EXIT: {node.name}", shape='doublecircle', color='red')

        # Visit function arguments (often ast.arguments)
        if node.args:
            # The 'arguments' object itself might not have lineno, but its children (ast.arg) do.
            # We'll create a node for the arguments summary.
            try:
                args_summary = ast.unparse(node.args).strip()
            except AttributeError: # Fallback for older Python versions or complex argument nodes
                args_summary = ", ".join([arg.arg for arg in node.args.args])

            args_node_id = self.new_node(f"ARGS: ({args_summary})", shape='rect', style='filled', fillcolor='lightgray')
            self.add_edge(self.current_node, args_node_id)
            self.current_node = args_node_id
            # No need to visit node.args directly here, ast.unparse summarizes it.

        # Visit the function body
        for stmt in node.body:
            prev_current = self.current_node
            self.visit(stmt)
            # FIX: Removed the 'and not self.dot.has_edge(prev_current, stmt._id)' check
            if prev_current is not None and stmt._id is not None:
                self.add_edge(prev_current, stmt._id)


        # After visiting all statements in body, connect the last current node to the function exit
        if self.current_node and self.current_node != self.function_exit_node_id:
            self.add_edge(self.current_node, self.function_exit_node_id)
        self.current_node = self.function_exit_node_id

    def visit_Return(self, node):
        # Connect the return statement to the function exit node
        return_node_id = node._id
        if self.current_node and self.current_node != return_node_id:
            self.add_edge(self.current_node, return_node_id) # Connect sequential flow to return
        if self.function_exit_node_id:
            self.add_edge(return_node_id, self.function_exit_node_id, label='Return')
        self.current_node = None # Terminate this branch's flow for sequential links

    def visit_If(self, node):
        test_node_id = node._id
        current_after_if_test = self.current_node # Save current_node before branches

        # Visit 'if' body
        if_body_entry_node_id = None
        if node.body:
            self.current_node = test_node_id # Start 'if' branch from test node
            self.visit(node.body[0]) # Visit first statement in 'if' body
            if_body_entry_node_id = node.body[0]._id
            if_body_exit_node_id = self.current_node
            self.add_edge(test_node_id, if_body_entry_node_id, label='True')
        else:
            if_body_exit_node_id = test_node_id # No 'if' body, 'true' path goes nowhere for now

        # Visit 'else' body (orelse can be elif or else)
        orelse_body_entry_node_id = None
        if node.orelse:
            self.current_node = test_node_id # Start 'else' branch from test node
            self.visit(node.orelse[0]) # Visit first statement in 'else' body
            orelse_body_entry_node_id = node.orelse[0]._id
            orelse_body_exit_node_id = self.current_node
            self.add_edge(test_node_id, orelse_body_entry_node_id, label='False')
        else:
            orelse_body_exit_node_id = test_node_id # No 'else' body, 'false' path goes nowhere for now
            self.add_edge(test_node_id, orelse_body_exit_node_id, label='False (No else)') # Implicit edge

        # After visiting branches, current_node should not be directly after the last branch.
        # This is where a proper merge node would be. For simplicity, we'll let subsequent generic_visit handle flow.
        # Reset current_node to before the If statement, assuming post-processing handles merges.
        self.current_node = current_after_if_test


    def visit_For(self, node):
        loop_header_node_id = node._id # The 'for' statement itself acts as the header/test
        current_before_loop = self.current_node # Save node before entering loop

        # Add edge to loop header
        if current_before_loop:
            self.add_edge(current_before_loop, loop_header_node_id)

        # Connect loop header to body
        if node.body:
            self.current_node = loop_header_node_id # Body starts from loop header
            self.visit(node.body[0]) # Visit first statement in loop body
            loop_body_entry_node_id = node.body[0]._id
            loop_body_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_body_entry_node_id, label='Enter Loop')
            self.add_edge(loop_body_exit_node_id, loop_header_node_id, label='Loop back') # Loop back from end of body
        else:
            loop_body_exit_node_id = loop_header_node_id # No body

        # The 'else' block for a for loop (executed if loop completes without break)
        if node.orelse:
            self.current_node = loop_header_node_id # Else branch starts from loop header
            self.visit(node.orelse[0]) # Visit first statement in orelse
            loop_else_entry_node_id = node.orelse[0]._id
            loop_else_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_else_entry_node_id, label='Else (No Break)')
        else:
            loop_else_exit_node_id = loop_header_node_id # No else body

        # Set current node to flow out of loop (this is where a merge would be)
        self.current_node = loop_header_node_id # For simple flow, flow out from header


    def visit_While(self, node):
        loop_header_node_id = node._id # The 'while' statement itself acts as the header/test
        current_before_loop = self.current_node # Save node before entering loop

        # Add edge to loop header
        if current_before_loop:
            self.add_edge(current_before_loop, loop_header_node_id)

        # Connect loop header to body
        if node.body:
            self.current_node = loop_header_node_id # Body starts from loop header
            self.visit(node.body[0])
            loop_body_entry_node_id = node.body[0]._id
            loop_body_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_body_entry_node_id, label='True')
            self.add_edge(loop_body_exit_node_id, loop_header_node_id, label='Loop back') # Loop back from end of body
        else:
            loop_body_exit_node_id = loop_header_node_id

        # The 'else' block for a while loop (executed if loop condition is initially false)
        if node.orelse:
            self.current_node = loop_header_node_id # Else branch starts from loop header
            self.visit(node.orelse[0])
            loop_else_entry_node_id = node.orelse[0]._id
            loop_else_exit_node_id = self.current_node
            self.add_edge(loop_header_node_id, loop_else_entry_node_id, label='False (Else)')
        else:
            loop_else_exit_node_id = loop_header_node_id # No else body
            self.add_edge(loop_header_node_id, loop_else_exit_node_id, label='False') # Path out of loop if false

        # Set current node to flow out of loop
        self.current_node = loop_header_node_id # For simple flow, flow out from header


# Main execution
if __name__ == "__main__":
    try:
        tree = ast.parse(code_to_analyze)
        code_lines = code_to_analyze.splitlines()

        dot = graphviz.Digraph(comment='Control Flow Graph', graph_attr={'rankdir': 'LR'})
        visitor = CFGVisitor(dot, code_lines)

        # Find the function node to start the visit
        # We assume the code_to_analyze contains only one function for simplicity
        function_found = False
        for node in ast.iter_child_nodes(tree): # Iterate top-level nodes
            if isinstance(node, ast.FunctionDef) and node.name == "analyze_user_behavior":
                visitor.visit_FunctionDef(node) # Call specific visitor for function
                function_found = True
                break
        
        if not function_found:
            print("Error: 'analyze_user_behavior' function not found in the provided code.")


        output_filename = "user_behavior_cfg_ast"
        dot_filepath = f"{output_filename}.dot"
        dot.render(dot_filepath, view=False, format='dot', cleanup=True)
        print(f"CFG .dot file generated: {dot_filepath}")

    except Exception as e:
        print(f"An error occurred during CFG generation: {e}")
        print("Please ensure your Python code is syntactically correct and Graphviz (system-wide) is installed and in your PATH.")
        print("Also, ensure 'astunparse' is installed if you are on Python < 3.9, as ast.unparse might be an issue without it.")