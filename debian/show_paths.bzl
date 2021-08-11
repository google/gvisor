"""Formatter to extract the output files from pkg_deb."""

def format(target):
    provider_map = providers(target)
    return "\n".join([
        provider_map["OutputGroupInfo"].out.to_list()[0].path,
        provider_map["OutputGroupInfo"].deb.to_list()[0].path,
        provider_map["OutputGroupInfo"].changes.to_list()[0].path,
    ])
