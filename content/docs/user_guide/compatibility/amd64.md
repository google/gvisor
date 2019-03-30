+++
title = "AMD64"
weight = 10
+++
This table is a reference of Linux syscalls for AMD64 and their compatibility
status in gVisor. gVisor does not support all syscalls and some syscalls may
have a partial implementation.

Of 329 syscalls, 47 syscalls have a full or partial implementation. There are
currently 51 unimplemented syscalls. 231 syscalls are not yet documented.

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
      <td><a class="doc-table-anchor" id="setpersonality"></a>135</td>
      <td><a href="http://man7.org/linux/man-pages/man2/setpersonality.2.html" target="_blank" rel="noopener">setpersonality</a></td>
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
      <td><a class="doc-table-anchor" id="schedsetparam"></a>142</td>
      <td><a href="http://man7.org/linux/man-pages/man2/schedsetparam.2.html" target="_blank" rel="noopener">schedsetparam</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="schedrrgetinterval"></a>148</td>
      <td><a href="http://man7.org/linux/man-pages/man2/schedrrgetinterval.2.html" target="_blank" rel="noopener">schedrrgetinterval</a></td>
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
      <td><a class="doc-table-anchor" id="modifyldt"></a>154</td>
      <td><a href="http://man7.org/linux/man-pages/man2/modifyldt.2.html" target="_blank" rel="noopener">modifyldt</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="pivotroot"></a>155</td>
      <td><a href="http://man7.org/linux/man-pages/man2/pivotroot.2.html" target="_blank" rel="noopener">pivotroot</a></td>
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
      <td><a class="doc-table-anchor" id="createmodule"></a>174</td>
      <td><a href="http://man7.org/linux/man-pages/man2/createmodule.2.html" target="_blank" rel="noopener">createmodule</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="initmodule"></a>175</td>
      <td><a href="http://man7.org/linux/man-pages/man2/initmodule.2.html" target="_blank" rel="noopener">initmodule</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="deletemodule"></a>176</td>
      <td><a href="http://man7.org/linux/man-pages/man2/deletemodule.2.html" target="_blank" rel="noopener">deletemodule</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="getkernelsyms"></a>177</td>
      <td><a href="http://man7.org/linux/man-pages/man2/getkernelsyms.2.html" target="_blank" rel="noopener">getkernelsyms</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Not supported in > 2.6</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="querymodule"></a>178</td>
      <td><a href="http://man7.org/linux/man-pages/man2/querymodule.2.html" target="_blank" rel="noopener">querymodule</a></td>
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
      <td><a class="doc-table-anchor" id="afssyscall"></a>183</td>
      <td><a href="http://man7.org/linux/man-pages/man2/afssyscall.2.html" target="_blank" rel="noopener">afssyscall</a></td>
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
      <td><a class="doc-table-anchor" id="setthreadarea"></a>205</td>
      <td><a href="http://man7.org/linux/man-pages/man2/setthreadarea.2.html" target="_blank" rel="noopener">setthreadarea</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Expected to return ENOSYS on 64-bit</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="getthreadarea"></a>211</td>
      <td><a href="http://man7.org/linux/man-pages/man2/getthreadarea.2.html" target="_blank" rel="noopener">getthreadarea</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Expected to return ENOSYS on 64-bit</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="lookupdcookie"></a>212</td>
      <td><a href="http://man7.org/linux/man-pages/man2/lookupdcookie.2.html" target="_blank" rel="noopener">lookupdcookie</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="epollctlold"></a>214</td>
      <td><a href="http://man7.org/linux/man-pages/man2/epollctlold.2.html" target="_blank" rel="noopener">epollctlold</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Deprecated</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="epollwaitold"></a>215</td>
      <td><a href="http://man7.org/linux/man-pages/man2/epollwaitold.2.html" target="_blank" rel="noopener">epollwaitold</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Deprecated</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="remapfilepages"></a>216</td>
      <td><a href="http://man7.org/linux/man-pages/man2/remapfilepages.2.html" target="_blank" rel="noopener">remapfilepages</a></td>
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
      <td><a class="doc-table-anchor" id="mqopen"></a>240</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mqopen.2.html" target="_blank" rel="noopener">mqopen</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mqunlink"></a>241</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mqunlink.2.html" target="_blank" rel="noopener">mqunlink</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mqtimedsend"></a>242</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mqtimedsend.2.html" target="_blank" rel="noopener">mqtimedsend</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mqtimedreceive"></a>243</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mqtimedreceive.2.html" target="_blank" rel="noopener">mqtimedreceive</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mqnotify"></a>244</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mqnotify.2.html" target="_blank" rel="noopener">mqnotify</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="mqgetsetattr"></a>245</td>
      <td><a href="http://man7.org/linux/man-pages/man2/mqgetsetattr.2.html" target="_blank" rel="noopener">mqgetsetattr</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="addkey"></a>248</td>
      <td><a href="http://man7.org/linux/man-pages/man2/addkey.2.html" target="_blank" rel="noopener">addkey</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EACCES; Not available to user</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="requestkey"></a>249</td>
      <td><a href="http://man7.org/linux/man-pages/man2/requestkey.2.html" target="_blank" rel="noopener">requestkey</a></td>
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
      <td><a class="doc-table-anchor" id="ioprioset"></a>251</td>
      <td><a href="http://man7.org/linux/man-pages/man2/ioprioset.2.html" target="_blank" rel="noopener">ioprioset</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="ioprioget"></a>252</td>
      <td><a href="http://man7.org/linux/man-pages/man2/ioprioget.2.html" target="_blank" rel="noopener">ioprioget</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_admin; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="migratepages"></a>256</td>
      <td><a href="http://man7.org/linux/man-pages/man2/migratepages.2.html" target="_blank" rel="noopener">migratepages</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_nice; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="setrobustlist"></a>273</td>
      <td><a href="http://man7.org/linux/man-pages/man2/setrobustlist.2.html" target="_blank" rel="noopener">setrobustlist</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Obsolete</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="getrobustlist"></a>274</td>
      <td><a href="http://man7.org/linux/man-pages/man2/getrobustlist.2.html" target="_blank" rel="noopener">getrobustlist</a></td>
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
      <td><a class="doc-table-anchor" id="movepages"></a>279</td>
      <td><a href="http://man7.org/linux/man-pages/man2/movepages.2.html" target="_blank" rel="noopener">movepages</a></td>
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
      <td><a class="doc-table-anchor" id="perfeventopen"></a>298</td>
      <td><a href="http://man7.org/linux/man-pages/man2/perfeventopen.2.html" target="_blank" rel="noopener">perfeventopen</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns ENODEV; No support for perf counters</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="fanotifyinit"></a>300</td>
      <td><a href="http://man7.org/linux/man-pages/man2/fanotifyinit.2.html" target="_blank" rel="noopener">fanotifyinit</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Needs CONFIG_FANOTIFY</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="fanotifymark"></a>301</td>
      <td><a href="http://man7.org/linux/man-pages/man2/fanotifymark.2.html" target="_blank" rel="noopener">fanotifymark</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS; Needs CONFIG_FANOTIFY</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="nametohandleat"></a>303</td>
      <td><a href="http://man7.org/linux/man-pages/man2/nametohandleat.2.html" target="_blank" rel="noopener">nametohandleat</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EOPNOTSUPP; Needs filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="openbyhandleat"></a>304</td>
      <td><a href="http://man7.org/linux/man-pages/man2/openbyhandleat.2.html" target="_blank" rel="noopener">openbyhandleat</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EOPNOTSUPP; Needs filesystem support</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="clockadjtime"></a>305</td>
      <td><a href="http://man7.org/linux/man-pages/man2/clockadjtime.2.html" target="_blank" rel="noopener">clockadjtime</a></td>
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
      <td><a class="doc-table-anchor" id="processvmreadv"></a>310</td>
      <td><a href="http://man7.org/linux/man-pages/man2/processvmreadv.2.html" target="_blank" rel="noopener">processvmreadv</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="processvmwritev"></a>311</td>
      <td><a href="http://man7.org/linux/man-pages/man2/processvmwritev.2.html" target="_blank" rel="noopener">processvmwritev</a></td>
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
      <td><a class="doc-table-anchor" id="finitmodule"></a>313</td>
      <td><a href="http://man7.org/linux/man-pages/man2/finitmodule.2.html" target="_blank" rel="noopener">finitmodule</a></td>
      <td>Partial</td>
      <td></td>
      <td>Returns EPERM or ENOSYS; Returns EPERM if the process does not have cap_sys_module; ENOSYS otherwise</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="schedsetattr"></a>314</td>
      <td><a href="http://man7.org/linux/man-pages/man2/schedsetattr.2.html" target="_blank" rel="noopener">schedsetattr</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
    <tr>
      <td><a class="doc-table-anchor" id="schedgetattr"></a>315</td>
      <td><a href="http://man7.org/linux/man-pages/man2/schedgetattr.2.html" target="_blank" rel="noopener">schedgetattr</a></td>
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
      <td><a class="doc-table-anchor" id="memfdcreate"></a>319</td>
      <td><a href="http://man7.org/linux/man-pages/man2/memfdcreate.2.html" target="_blank" rel="noopener">memfdcreate</a></td>
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
      <td><a class="doc-table-anchor" id="copyfilerange"></a>326</td>
      <td><a href="http://man7.org/linux/man-pages/man2/copyfilerange.2.html" target="_blank" rel="noopener">copyfilerange</a></td>
      <td>Unimplemented</td>
      <td></td>
      <td>Returns ENOSYS</td>
    </tr>
  </tbody>
</table>
