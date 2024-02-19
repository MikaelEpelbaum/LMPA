
chosen_func_prompt = "Can you help me guess some information for the following decompiled C function from a binary program?" \
        " The following is the decompiled C function: \n{decompiler_output}" \
        " In the above function, what are good names for \n{params}, respectively?" \
        " You must follow the format \n{format} and return a valid JSON with (use double quotes only)." \
        " DON'T INCLUDE CHANGES OF VARIABLES CONVENTIONAL NAMINGS" \
        " keep only high level confidence levels. RETURN ONLY MEANINGFUL CHANGES"

comment_prompt = "/* Called in {function_name} with input: {variables} */ "