"""Formatter to extract the output files from a target."""

def format(target):
    provider_map = providers(target)
    if not provider_map:
        return ""
    outputs = dict()

    prefix = ""
    if target.label.package:
        prefix = target.label.package + "/"
    prefix = prefix + target.label.name + "/"

    # Try to resolve in order.
    files_to_run = provider_map.get("FilesToRunProvider", None)
    default_info = provider_map.get("DefaultInfo", None)
    output_group_info = provider_map.get("OutputGroupInfo", None)
    if files_to_run and files_to_run.executable:
        outputs[files_to_run.executable.path] = files_to_run.executable.basename
    elif default_info:
        for x in default_info.files.to_list():
            rel = x.short_path
            if rel.startswith(prefix):
                rel = rel[len(prefix):]
            else:
                rel = x.basename
            outputs[x.path] = rel
    elif output_group_info:
        for entry in dir(output_group_info):
            # Filter out all built-ins and anything that is not a depset.
            if entry.startswith("_") or not hasattr(getattr(output_group_info, entry), "to_list"):
                continue
            for x in getattr(output_group_info, entry).to_list():
                outputs[x.path] = x.basename

    # Return all found files with their relative destination paths.
    return "\n".join(["%s %s" % (k, v) for k, v in outputs.items()])
