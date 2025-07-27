# python-testing

This project provides a Python script to analyze a given function's complexity and visualize its control flow. It leverages the radon library for cyclomatic complexity calculation and the ast (Abstract Syntax Tree) and graphviz libraries for generating a visual Control Flow Graph (CFG).

✨ Features
Cyclomatic Complexity Calculation: Computes the cyclomatic complexity of the analyze_user_behavior function using the radon package, providing a quantitative measure of its structural complexity.

Control Flow Graph (CFG) Visualization: Generates a .dot file representing the function's control flow, which can be rendered into a visual graph (e.g., PNG, SVG) using Graphviz.

Detailed Node Information: CFG nodes include line numbers and snippets of the corresponding code for easier understanding.

Entry/Exit Nodes: Clearly marks the function's entry and exit points in the CFG.

🚀 Prerequisites
Before you begin, ensure you have the following installed on your system:

Python 3.x: Download and install from python.org. Make sure to check "Add Python to PATH" during installation.

pip: Python's package installer (usually comes with Python).

Graphviz (System-wide Installation): This is essential for rendering the .dot files into actual graphs.

Windows: Download the installer from Graphviz Downloads. During installation, ensure you select "Add Graphviz to the system PATH for all users." Restart your terminal/command prompt after installation.

macOS (using Homebrew): brew install graphviz

Linux (Debian/Ubuntu): sudo apt-get update && sudo apt-get install graphviz

Verification: Open a new terminal/command prompt and run dot -V. You should see version information.

VS Code (Recommended): For editing the script and viewing the generated .dot files.

Graphviz Preview Extension for VS Code: In VS Code, go to Extensions (Ctrl+Shift+X), search for "Graphviz Preview" (by joaompneves or similar), and install it.

📦 Setup & Installation
Save the Python Script:

Create a new file named analyze_code.py (or generate_ast_cfg.py if you prefer to keep the original name) in a convenient directory (e.g., my_code_analyzer folder on your desktop).

Paste the entire Python code provided in the previous response into this file.

Save the file.

Install Python Packages:

Open your terminal or command prompt.

Navigate to the directory where you saved analyze_code.py.

cd path/to/your/directory
# Example: cd C:\Users\YourUser\Desktop\my_code_analyzer

Install the required Python libraries:

pip install radon graphviz astunparse

Note on astunparse: This is primarily needed for Python versions older than 3.9. If you're on Python 3.9+, ast.unparse is built-in. Installing it won't hurt.

Troubleshooting pip install errors (especially on Windows): If pip install fails with C++ compiler errors (e.g., "Microsoft Visual C++ 14.0 or greater is required", "Cannot open include file: 'io.h'" or "'graphviz/cgraph.h'"), refer to the Troubleshooting section below.

🚀 Usage
Run the Script:

Open your terminal or command prompt.

Navigate to the directory containing analyze_code.py.

Execute the script:

python analyze_code.py

Interpret Output:

The script will first print the Cyclomatic Complexity of the analyze_user_behavior function to your console. Example:

--- Cyclomatic Complexity (Radon) ---
Function: analyze_user_behavior, Complexity: 22

It will then confirm the creation of the CFG .dot file:

CFG .dot file generated: user_behavior_cfg_radon.dot

View the Control Flow Graph:

Option A (Recommended - Online Viewer):

Open user_behavior_cfg_radon.dot in a text editor (like VS Code).

Copy all its content.

Go to an online Graphviz viewer (e.g., GraphvizOnline or Edotor).

Paste the content into the text area. The graph will be rendered automatically.

Option B (VS Code Extension):

In VS Code, open the user_behavior_cfg_radon.dot file (File > Open File...).

The "Graphviz Preview" extension should automatically render the graph in a new pane. If not, right-click the .dot file in the Explorer and look for a "Preview Graphviz" option.

Option C (Command Line to Image):

In your terminal (in the same directory), run:

dot -Tpng user_behavior_cfg_radon.dot -o user_behavior_cfg_radon.png
# Or for SVG:
dot -Tsvg user_behavior_cfg_radon.dot -o user_behavior_cfg_radon.svg

An image file (.png or .svg) will be created, which you can open with any image viewer.

⚠️ Troubleshooting
Here are solutions for common issues you might encounter:

radon / python -m radon / dot not recognized
Problem: radon or dot command not found.

Solution: This means the executable is not in your system's PATH.

For radon: Try running python -m radon cc analyze_code.py instead of just radon cc.

For dot: Ensure Graphviz (system-wide) is correctly installed and its installation directory (specifically the bin folder) is added to your system's PATH. Restart your terminal/command prompt after modifying PATH.

ModuleNotFoundError: No module named '...'
Problem: Python cannot find a required library (e.g., astunparse, graphviz).

Solution: Install the missing package using pip:

pip install <missing_module_name>
# Example: pip install astunparse

error: Microsoft Visual C++ 14.0 or greater is required (on Windows)
Problem: Python packages requiring C/C++ compilation (like pygraphviz if we were using it, or other underlying dependencies) cannot find a compiler.

Solution:

Download and install "Microsoft C++ Build Tools" from visualstudio.microsoft.com/visual-cpp-build-tools/.

During installation, select the "Desktop development with C++" workload.

Restart your computer after installation to ensure PATH variables are updated.

Then, retry pip install commands.

fatal error C1083: Cannot open include file: 'io.h' (on Windows)
Problem: C++ compiler cannot find standard Windows SDK header files.

Solution:

Open "Visual Studio Installer" (search in Start Menu).

Click "Modify" on your "Visual Studio Build Tools" installation.

Go to "Individual components" and ensure a "Windows SDK" (e.g., "Windows 11 SDK") is checked and installed.

Crucially, use the "Developer Command Prompt for VS 2022" (or similar, from your Start Menu) when running pip install commands, as it sets up the correct environment variables for compilation.

fatal error C1083: Cannot open include file: 'graphviz/cgraph.h' (on Windows)
Problem: C++ compiler cannot find Graphviz's own header files.

Solution:

Ensure Graphviz (system-wide) is installed and you know its root installation path (e.g., C:\Program Files\Graphviz).

Open the "x64 Native Tools Command Prompt for VS 2022" (or similar 64-bit developer prompt) from your Start Menu.

Before running pip install, set these environment variables in that prompt (adjust paths to your actual Graphviz installation):

set GRAPHVIZ_DOT="C:\Program Files\Graphviz\bin\dot.exe"
set GRAPHVIZ_INCLUDE_PATH="C:\Program Files\Graphviz\include"
set GRAPHVIZ_LIBRARY_PATH="C:\Program Files\Graphviz\lib"

Then, run pip install graphviz (or your main script) in the same prompt.

IndentationError: expected an indented block
Problem: Python's strict indentation rules are violated, often due to mixed spaces/tabs or incorrect spacing.

Solution:

In VS Code, enable "Render Whitespace" (View -> Render Whitespace) to see hidden characters.

Carefully re-indent the problematic line and the block following it using 4 spaces for each indentation level.

Use VS Code's "Convert Indentation to Spaces" command (from Command Palette: Ctrl+Shift+P / Cmd+Shift+P, then type "indent").

CFGVisitor.new_node() got an unexpected keyword argument 'fillcolor'
Problem: The new_node method was called with fillcolor but its definition didn't accept it.

Solution: This was addressed in the provided code. Ensure your new_node method definition matches the latest version in the script, specifically including fillcolor=None in its parameters.

📝 Notes and Limitations
The generated CFG is a simplified representation focusing on major control flow constructs (if, for, while, function entry/exit, return). It may not capture every subtle detail of Python's execution model (e.g., exceptions, complex jumps).

The ast.unparse function (used for node labels) is available in Python 3.9+. For older Python versions, you might need to install astunparse (pip install astunparse). The script includes a try-except block for this.

The graphviz Python library (used here) is a binding to the system-wide Graphviz tool. Therefore, the system-wide Graphviz installation is a hard requirement.
