+++
title = "AMD64"
description = "Syscall Compatibility Reference Documentation for AMD64"
weight = 10
+++

This table is a reference of Linux syscalls for the AMD64 architecture and
their compatibility status in gVisor. gVisor does not support all syscalls and
some syscalls may have a partial implementation.

Of 329 syscalls, 47 syscalls have a full or partial
implementation. There are currently 51 unimplemented
syscalls. 231 syscalls are not yet documented.

<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Name</th>
      <th>Support</th>
      <th>GitHub Issue</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><a class="doc-table-anchor" id="msgget"></a>68</td>
      <td><a href="http://man7.org/linux/man-pages/man2/msgget.2.html" target="_blank" rel="noopener">msgget</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="msgsnd"></a>69</td>
      <td><a href="http://man7.org/linux/man-pages/man2/msgsnd.2.html" target="_blank" rel="noopener">msgsnd</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="msgrcv"></a>70</td>
      <td><a href="http://man7.org/linux/man-pages/man2/msgrcv.2.html" target="_blank" rel="noopener">msgrcv</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="msgctl"></a>71</td>
      <td><a href="http://man7.org/linux/man-pages/man2/msgctl.2.html" target="_blank" rel="noopener">msgctl</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="setfsuid"></a>122</td>
      <td><a href="http://man7.org/linux/man-pages/man2/setfsuid.2.html" target="_blank" rel="noopener">setfsuid</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="setfsgid"></a>123</td>
      <td><a href="http://man7.org/linux/man-pages/man2/setfsgid.2.html" target="_blank" rel="noopener">setfsgid</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="uselib"></a>134</td>
      <td><a href="http://man7.org/linux/man-pages/man2/uselib.2.html" target="_blank" rel="noopener">uselib</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Obsolete</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="personality"></a>135</td>
      <td><a href="http://man7.org/linux/man-pages/man2/personality.2.html" target="_blank" rel="noopener">personality</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EINVAL; Unable to change personality</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="ustat"></a>136</td>
      <td><a href="http://man7.org/linux/man-pages/man2/ustat.2.html" target="_blank" rel="noopener">ustat</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Needs filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="sysfs"></a>139</td>
      <td><a href="http://man7.org/linux/man-pages/man2/sysfs.2.html" target="_blank" rel="noopener">sysfs</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="sched_setparam"></a>142</td>
      <td><a href="http://man7.org/linux/man-pages/man2/sched_setparam.2.html" target="_blank" rel="noopener">sched_setparam</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="schedrrgetinterval"></a>148</td>
      <td><a href="http://man7.org/linux/man-pages/man2/sched_rr_get_interval.2.html" target="_blank" rel="noopener">sched_rr_get_interval</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="vhangup"></a>153</td>
      <td><a href="http://man7.org/linux/man-pages/man2/vhangup.2.html" target="_blank" rel="noopener">vhangup</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="modify_ldt"></a>154</td>
      <td><a href="http://man7.org/linux/man-pages/man2/modify_ldt.2.html" target="_blank" rel="noopener">modify_ldt</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="pivot_root"></a>155</td>
      <td><a href="http://man7.org/linux/man-pages/man2/pivot_root.2.html" target="_blank" rel="noopener">pivot_root</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="sysctl"></a>156</td>
      <td><a href="http://man7.org/linux/man-pages/man2/sysctl.2.html" target="_blank" rel="noopener">sysctl</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="adjtimex"></a>159</td>
      <td><a href="http://man7.org/linux/man-pages/man2/adjtimex.2.html" target="_blank" rel="noopener">adjtimex</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_time; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="acct"></a>163</td>
      <td><a href="http://man7.org/linux/man-pages/man2/acct.2.html" target="_blank" rel="noopener">acct</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_pacct; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="settimeofday"></a>164</td>
      <td><a href="http://man7.org/linux/man-pages/man2/settimeofday.2.html" target="_blank" rel="noopener">settimeofday</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_time; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="swapon"></a>167</td>
      <td><a href="http://man7.org/linux/man-pages/man2/swapon.2.html" target="_blank" rel="noopener">swapon</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="swapoff"></a>168</td>
      <td><a href="http://man7.org/linux/man-pages/man2/swapoff.2.html" target="_blank" rel="noopener">swapoff</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="reboot"></a>169</td>
      <td><a href="http://man7.org/linux/man-pages/man2/reboot.2.html" target="_blank" rel="noopener">reboot</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_boot; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="iopl"></a>172</td>
      <td><a href="http://man7.org/linux/man-pages/man2/iopl.2.html" target="_blank" rel="noopener">iopl</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_rawio; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="ioperm"></a>173</td>
      <td><a href="http://man7.org/linux/man-pages/man2/ioperm.2.html" target="_blank" rel="noopener">ioperm</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_rawio; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="create_module"></a>174</td>
      <td><a href="http://man7.org/linux/man-pages/man2/create_module.2.html" target="_blank" rel="noopener">create_module</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="init_module"></a>175</td>
      <td><a href="http://man7.org/linux/man-pages/man2/init_module.2.html" target="_blank" rel="noopener">init_module</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="delete_module"></a>176</td>
      <td><a href="http://man7.org/linux/man-pages/man2/delete_module.2.html" target="_blank" rel="noopener">delete_module</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="get_kernel_syms"></a>177</td>
      <td><a href="http://man7.org/linux/man-pages/man2/get_kernel_syms.2.html" target="_blank" rel="noopener">get_kernel_syms</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not supported in > 2.6</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="query_module"></a>178</td>
      <td><a href="http://man7.org/linux/man-pages/man2/query_module.2.html" target="_blank" rel="noopener">query_module</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not supported in > 2.6</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="quotactl"></a>179</td>
      <td><a href="http://man7.org/linux/man-pages/man2/quotactl.2.html" target="_blank" rel="noopener">quotactl</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="nfsservctl"></a>180</td>
      <td><a href="http://man7.org/linux/man-pages/man2/nfsservctl.2.html" target="_blank" rel="noopener">nfsservctl</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Does not exist > 3.1</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="getpmsg"></a>181</td>
      <td><a href="http://man7.org/linux/man-pages/man2/getpmsg.2.html" target="_blank" rel="noopener">getpmsg</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not implemented in Linux</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="putpmsg"></a>182</td>
      <td><a href="http://man7.org/linux/man-pages/man2/putpmsg.2.html" target="_blank" rel="noopener">putpmsg</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not implemented in Linux</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="afs_syscall"></a>183</td>
      <td><a href="http://man7.org/linux/man-pages/man2/afs_syscall.2.html" target="_blank" rel="noopener">afs_syscall</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not implemented in Linux</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="tuxcall"></a>184</td>
      <td><a href="http://man7.org/linux/man-pages/man2/tuxcall.2.html" target="_blank" rel="noopener">tuxcall</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not implemented in Linux</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="security"></a>185</td>
      <td><a href="http://man7.org/linux/man-pages/man2/security.2.html" target="_blank" rel="noopener">security</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not implemented in Linux</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="readahead"></a>187</td>
      <td><a href="http://man7.org/linux/man-pages/man2/readahead.2.html" target="_blank" rel="noopener">readahead</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="setxattr"></a>188</td>
      <td><a href="http://man7.org/linux/man-pages/man2/setxattr.2.html" target="_blank" rel="noopener">setxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="lsetxattr"></a>189</td>
      <td><a href="http://man7.org/linux/man-pages/man2/lsetxattr.2.html" target="_blank" rel="noopener">lsetxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="fsetxattr"></a>190</td>
      <td><a href="http://man7.org/linux/man-pages/man2/fsetxattr.2.html" target="_blank" rel="noopener">fsetxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="getxattr"></a>191</td>
      <td><a href="http://man7.org/linux/man-pages/man2/getxattr.2.html" target="_blank" rel="noopener">getxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="lgetxattr"></a>192</td>
      <td><a href="http://man7.org/linux/man-pages/man2/lgetxattr.2.html" target="_blank" rel="noopener">lgetxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="fgetxattr"></a>193</td>
      <td><a href="http://man7.org/linux/man-pages/man2/fgetxattr.2.html" target="_blank" rel="noopener">fgetxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="listxattr"></a>194</td>
      <td><a href="http://man7.org/linux/man-pages/man2/listxattr.2.html" target="_blank" rel="noopener">listxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="llistxattr"></a>195</td>
      <td><a href="http://man7.org/linux/man-pages/man2/llistxattr.2.html" target="_blank" rel="noopener">llistxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="flistxattr"></a>196</td>
      <td><a href="http://man7.org/linux/man-pages/man2/flistxattr.2.html" target="_blank" rel="noopener">flistxattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="removexattr"></a>197</td>
      <td><a href="http://man7.org/linux/man-pages/man2/removexattr.2.html" target="_blank" rel="noopener">removexattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="lremovexattr"></a>198</td>
      <td><a href="http://man7.org/linux/man-pages/man2/lremovexattr.2.html" target="_blank" rel="noopener">lremovexattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="fremovexattr"></a>199</td>
      <td><a href="http://man7.org/linux/man-pages/man2/fremovexattr.2.html" target="_blank" rel="noopener">fremovexattr</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENOTSUP; Requires filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="set_thread_area"></a>205</td>
      <td><a href="http://man7.org/linux/man-pages/man2/set_thread_area.2.html" target="_blank" rel="noopener">set_thread_area</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Expected to return ENOSYS on 64-bit</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="get_thread_area"></a>211</td>
      <td><a href="http://man7.org/linux/man-pages/man2/get_thread_area.2.html" target="_blank" rel="noopener">get_thread_area</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Expected to return ENOSYS on 64-bit</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="lookup_dcookie"></a>212</td>
      <td><a href="http://man7.org/linux/man-pages/man2/lookup_dcookie.2.html" target="_blank" rel="noopener">lookup_dcookie</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="epoll_ctl_old"></a>214</td>
      <td>epoll_ctl_old</td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Deprecated</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="epoll_wait_old"></a>215</td>
      <td>epoll_wait_old</td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Deprecated</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="remap_file_pages"></a>216</td>
      <td><a href="http://man7.org/linux/man-pages/man2/remap_file_pages.2.html" target="_blank" rel="noopener">remap_file_pages</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Deprecated</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="semtimedop"></a>220</td>
      <td><a href="http://man7.org/linux/man-pages/man2/semtimedop.2.html" target="_blank" rel="noopener">semtimedop</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="vserver"></a>236</td>
      <td><a href="http://man7.org/linux/man-pages/man2/vserver.2.html" target="_blank" rel="noopener">vserver</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not implemented by Linux</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mbind"></a>237</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mbind.2.html" target="_blank" rel="noopener">mbind</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mq_open"></a>240</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mq_open.2.html" target="_blank" rel="noopener">mq_open</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mq_unlink"></a>241</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mq_unlink.2.html" target="_blank" rel="noopener">mq_unlink</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mq_timedsend"></a>242</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mq_timedsend.2.html" target="_blank" rel="noopener">mq_timedsend</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mq_timedreceive"></a>243</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mq_timedreceive.2.html" target="_blank" rel="noopener">mq_timedreceive</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mq_notify"></a>244</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mq_notify.2.html" target="_blank" rel="noopener">mq_notify</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mq_getsetattr"></a>245</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mq_getsetattr.2.html" target="_blank" rel="noopener">mq_getsetattr</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="add_key"></a>248</td>
      <td><a href="http://man7.org/linux/man-pages/man2/add_key.2.html" target="_blank" rel="noopener">add_key</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EACCES; Not available to user</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="request_key"></a>249</td>
      <td><a href="http://man7.org/linux/man-pages/man2/request_key.2.html" target="_blank" rel="noopener">request_key</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EACCES; Not available to user</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="keyctl"></a>250</td>
      <td><a href="http://man7.org/linux/man-pages/man2/keyctl.2.html" target="_blank" rel="noopener">keyctl</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EACCES; Not available to user</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="ioprio_set"></a>251</td>
      <td><a href="http://man7.org/linux/man-pages/man2/ioprio_set.2.html" target="_blank" rel="noopener">ioprio_set</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="ioprio_get"></a>252</td>
      <td><a href="http://man7.org/linux/man-pages/man2/ioprio_get.2.html" target="_blank" rel="noopener">ioprio_get</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="migrate_pages"></a>256</td>
      <td><a href="http://man7.org/linux/man-pages/man2/migrate_pages.2.html" target="_blank" rel="noopener">migrate_pages</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="set_robust_list"></a>273</td>
      <td><a href="http://man7.org/linux/man-pages/man2/set_robust_list.2.html" target="_blank" rel="noopener">set_robust_list</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Obsolete</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="get_robust_list"></a>274</td>
      <td><a href="http://man7.org/linux/man-pages/man2/get_robust_list.2.html" target="_blank" rel="noopener">get_robust_list</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Obsolete</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="splice"></a>275</td>
      <td><a href="http://man7.org/linux/man-pages/man2/splice.2.html" target="_blank" rel="noopener">splice</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="tee"></a>276</td>
      <td><a href="http://man7.org/linux/man-pages/man2/tee.2.html" target="_blank" rel="noopener">tee</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="vmsplice"></a>278</td>
      <td><a href="http://man7.org/linux/man-pages/man2/vmsplice.2.html" target="_blank" rel="noopener">vmsplice</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="move_pages"></a>279</td>
      <td><a href="http://man7.org/linux/man-pages/man2/move_pages.2.html" target="_blank" rel="noopener">move_pages</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="signalfd"></a>282</td>
      <td><a href="http://man7.org/linux/man-pages/man2/signalfd.2.html" target="_blank" rel="noopener">signalfd</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="signalfd4"></a>289</td>
      <td><a href="http://man7.org/linux/man-pages/man2/signalfd4.2.html" target="_blank" rel="noopener">signalfd4</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="perf_event_open"></a>298</td>
      <td><a href="http://man7.org/linux/man-pages/man2/perf_event_open.2.html" target="_blank" rel="noopener">perf_event_open</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENODEV; No support for perf counters</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="fanotify_init"></a>300</td>
      <td><a href="http://man7.org/linux/man-pages/man2/fanotify_init.2.html" target="_blank" rel="noopener">fanotify_init</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Needs CONFIG_FANOTIFY</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="fanotify_mark"></a>301</td>
      <td><a href="http://man7.org/linux/man-pages/man2/fanotify_mark.2.html" target="_blank" rel="noopener">fanotify_mark</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Needs CONFIG_FANOTIFY</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="name_to_handle_at"></a>303</td>
      <td><a href="http://man7.org/linux/man-pages/man2/name_to_handle_at.2.html" target="_blank" rel="noopener">name_to_handle_at</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EOPNOTSUPP; Needs filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="open_by_handle_at"></a>304</td>
      <td><a href="http://man7.org/linux/man-pages/man2/open_by_handle_at.2.html" target="_blank" rel="noopener">open_by_handle_at</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EOPNOTSUPP; Needs filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="clock_adjtime"></a>305</td>
      <td>clock_adjtime</td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="setns"></a>308</td>
      <td><a href="http://man7.org/linux/man-pages/man2/setns.2.html" target="_blank" rel="noopener">setns</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="process_vm_readv"></a>310</td>
      <td><a href="http://man7.org/linux/man-pages/man2/process_vm_readv.2.html" target="_blank" rel="noopener">process_vm_readv</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="process_vm_writev"></a>311</td>
      <td><a href="http://man7.org/linux/man-pages/man2/process_vm_writev.2.html" target="_blank" rel="noopener">process_vm_writev</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="kcmp"></a>312</td>
      <td><a href="http://man7.org/linux/man-pages/man2/kcmp.2.html" target="_blank" rel="noopener">kcmp</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Requires cap_sys_ptrace</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="finit_module"></a>313</td>
      <td><a href="http://man7.org/linux/man-pages/man2/finit_module.2.html" target="_blank" rel="noopener">finit_module</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="sched_setattr"></a>314</td>
      <td><a href="http://man7.org/linux/man-pages/man2/sched_setattr.2.html" target="_blank" rel="noopener">sched_setattr</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="sched_getattr"></a>315</td>
      <td><a href="http://man7.org/linux/man-pages/man2/sched_getattr.2.html" target="_blank" rel="noopener">sched_getattr</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="renameat2"></a>316</td>
      <td><a href="http://man7.org/linux/man-pages/man2/renameat2.2.html" target="_blank" rel="noopener">renameat2</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="memfd_create"></a>319</td>
      <td><a href="http://man7.org/linux/man-pages/man2/memfd_create.2.html" target="_blank" rel="noopener">memfd_create</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="bpf"></a>321</td>
      <td><a href="http://man7.org/linux/man-pages/man2/bpf.2.html" target="_blank" rel="noopener">bpf</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_boot; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="execveat"></a>322</td>
      <td><a href="http://man7.org/linux/man-pages/man2/execveat.2.html" target="_blank" rel="noopener">execveat</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="userfaultfd"></a>323</td>
      <td><a href="http://man7.org/linux/man-pages/man2/userfaultfd.2.html" target="_blank" rel="noopener">userfaultfd</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="membarrier"></a>324</td>
      <td><a href="http://man7.org/linux/man-pages/man2/membarrier.2.html" target="_blank" rel="noopener">membarrier</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="copy_file_range"></a>326</td>
      <td><a href="http://man7.org/linux/man-pages/man2/copy_file_range.2.html" target="_blank" rel="noopener">copy_file_range</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
  </tbody>
</table>
