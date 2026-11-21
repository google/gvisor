set pagination off
set confirm off
python assert gdb.selected_frame().name() is not None, "unknown frame at attach"
tbreak check_after_attach
set variable attached = 1
continue
break check_pid
continue
stepi
if $pc != (void *)&check_pid_syscall
  quit 1
end
stepi
continue
stepi
if $pc != (void *)&check_pid_syscall
  quit 1
end
stepi
continue
if $_isvoid($_exitcode)
  quit 1
end
if $_exitcode != 0
  quit 1
end
echo debugger attach and single-step succeeded\n
