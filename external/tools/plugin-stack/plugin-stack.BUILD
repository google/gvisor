config_setting(
    name = "plugin_tldk_condition",
    values = {"define": "plugin_tldk=true"},
)

genrule(
    name = "pluginstack_genrule",
    outs = ["libpluginstack.a"],
    cmd = select({
        # Support IVB and later machines.
        ":plugin_tldk_condition": "git clone https://github.com/alipay/tldk.git && " +
                                  "cd tldk && " +
                                  "git checkout cec8ff773c2ee609a1fcbc389aecb4dbb4e3bb88 && " +
                                  "make -j 4 DPDK_GIT_REPO='https://github.com/DPDK/dpdk' DPDK_MACHINE=ivb EXTRA_CFLAGS='-g -O3 -fPIC -fno-omit-frame-pointer -DLOOK_ASIDE_BACKEND -Wno-error -Wno-use-after-free' all && " +
                                  "cd .. && " +
                                  "cp -f tldk/libtldk.a $(RULEDIR)/libpluginstack.a",
        "//conditions:default": "",
    }),
    local = 1,
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libpluginstack",
    srcs = ["libpluginstack.a"],
    visibility = ["//visibility:public"],
)
