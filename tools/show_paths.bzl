"""Formatter to extract the output files from a target."""

def format(target):
    provider_map = providers(target)
    outputs = dict()

    # Try to resolve in order.
    files_to_run = provider_map.get("FilesToRunProvider", None)
    default_info = provider_map.get("DefaultInfo", None)
    output_group_info = provider_map.get("OutputGroupInfo", None)
    if files_to_run and files_to_run.executable:
        outputs[files_to_run.executable.path] = True
    elif default_info:
        for x in default_info.files:
            outputs[x.path] = True
    elif output_group_info:
        for entry in dir(output_group_info):
            # Filter out all built-ins and anything that is not a depset.
            if entry.startswith("_") or not hasattr(getattr(output_group_info, entry), "to_list"):
                continue
            for x in getattr(output_group_info, entry).to_list():
                outputs[x.path] = True

    # Return all found files.
    return "\n".join(outputs.keys())
