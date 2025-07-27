import ast
import graphviz
from pycfg.pycfg import PyCFG, CFGNode

def generate_cfg_dot(code_string, function_name, output_filename_prefix):
    """
    Generates a Control Flow Graph (CFG) in .dot format for a given Python code string.

    Args:
        code_string (str): The Python code as a string.
        function_name (str): The name of the function to analyze (for graph title).
        output_filename_prefix (str): Prefix for the output .dot file (e.g., "my_function_cfg").
    """
    try:
        # Build the CFG using pycfg
        cfg = PyCFG()
        cfg.build_from_src(code_string)

        # Create a Digraph object from graphviz
        dot = graphviz.Digraph(comment=f'CFG for {function_name}')
        dot.attr(rankdir='LR', # Layout direction: Left to Right
                 labelloc='t', # Label location: top
                 label=f'Control Flow Graph for "{function_name}"',
                 fontsize='20')

        # Add nodes to the graph
        for node_id, node in cfg.nodes.items():
            # Clean up the block text for display
            label = node.block.replace(';', '\\n').strip()
            if not label: # Handle empty blocks
                label = f"Node {node_id}"

            # Assign a shape based on node type (optional, but makes it clearer)
            shape = 'box'
            if node.is_entry:
                shape = 'ellipse'
            elif node.is_exit:
                shape = 'doublecircle'
            elif node.is_decision: # Nodes with multiple successors (e.g., if, while)
                shape = 'diamond'

            dot.node(str(node_id), label, shape=shape, style='rounded', fontname='Inter')

        # Add edges to the graph
        for node_id, node in cfg.nodes.items():
            for successor_id in node.successors:
                dot.edge(str(node_id), str(successor_id))

        # Render the graph to a .dot file
        dot_filepath = f"{output_filename_prefix}.dot"
        dot.render(dot_filepath, view=False, format='dot', cleanup=True) # cleanup=True removes intermediate files
        print(f"CFG .dot file generated: {dot_filepath}")

    except Exception as e:
        print(f"An error occurred during CFG generation: {e}")
        print("Please ensure your Python code is syntactically correct and Graphviz is installed and in your PATH.")

# --- Your Python code to analyze ---
# It's important to provide the exact function code here
# If your function is in user_analysis.py, you can read it from there:
# with open('user_analysis.py', 'r') as f:
#     code_to_analyze = f.read()

code_to_analyze = """def analyze_user_behavior(users):
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
    return suspicious_users"""