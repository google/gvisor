config_setting(
    name = "plugin_tldk_condition",
    values = {"define": "plugin_tldk=true"},
)

genrule(
    name = "pluginstack_genrule",
    outs = ["libpluginstack.a"],
    local = 1,
    cmd = select({
        # Support IVB and later machines.
        ":plugin_tldk_condition": "git clone git@github.com:alipay/tldk.git; cd tldk; git checkout 9efb0dacb67da1da62ca78785e8cffb0c5a82785; make -j 1 DPDK_MACHINE=ivb EXTRA_CFLAGS='-g -O3 -fPIC -fno-omit-frame-pointer -DLOOK_ASIDE_BACKEND -Wno-error' all; cd ..; cp -f tldk/libtldk.a $(RULEDIR)/libpluginstack.a",
        "//conditions:default": "",
    }),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "libpluginstack",
    srcs = ["libpluginstack.a"],
    visibility = ["//visibility:public"],
)
