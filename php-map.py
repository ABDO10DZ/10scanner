import re

def parse_php_file(file_path):
    functions = {}

    with open(file_path, 'r') as file:
        php_code = file.read()

        # Regular expression pattern for matching function definitions
        function_pattern = r'function\s+([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\((.*?)\)\s*{([^}]*)}'

        # Find all function definitions in the PHP code
        function_matches = re.finditer(function_pattern, php_code, re.DOTALL)

        # Regular expression pattern for matching include statements
        include_pattern = r'(include|include_once|require|require_once)\s*["\']([^"\']+)["\']'

        # Find all include statements in the PHP code
        include_matches = re.finditer(include_pattern, php_code)

        for match in function_matches:
            function_name = match.group(1)
            function_params = match.group(2)
            function_body = match.group(3)

            # Regular expression pattern for matching variables within the function body
            variable_pattern = r'\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)'

            # Find all variables within the function body
            function_variables = re.findall(variable_pattern, function_params + function_body)

            # Add function variables to the dictionary
            functions[function_name] = {'variables': function_variables, 'subcalls': []}

            # Regular expression pattern for matching function calls within the function body
            call_pattern = r'\b([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)\s*\((.*?)\);'

            # Find all function calls within the function body
            function_calls = re.findall(call_pattern, function_body)

            # Add function calls to the dictionary
            functions[function_name]['subcalls'] = [{'name': call[0], 'variables': re.findall(variable_pattern, call[1])} for call in function_calls]

        for match in include_matches:
            include_type = match.group(1)
            include_path = match.group(2)
            functions[include_path] = include_type

    return functions

def map(path):
    functions = parse_php_file(path)
    print("Functions:")
    for func_name, data in functions.items():
        if isinstance(data, dict):
            print("Main Function:", func_name)
            print("Variables:", data['variables'])
            print("Subcalls:")
            for subcall in data['subcalls']:
                print("\tSubcall:", subcall['name'])
                print("\tVariables:", subcall['variables'])
        else:
            print("Include:", func_name, "| Type:", data)


# usage map(path2.php)
