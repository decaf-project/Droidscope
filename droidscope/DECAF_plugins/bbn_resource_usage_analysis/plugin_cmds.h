{
  .name         = "do_hookapitests",
  .args_type    = _QEMU_MON_KEY_VALUE("procname","s"),
  ._QEMU_MON_HANDLER_CMD = do_hookapitests,
  .params       = "[procname]",
  .help	        = "Start tracing process with name [process_name]"
},
{
  .name         = "clear_log",
  .args_type    = _QEMU_MON_KEY_VALUE("procname","s"),
  ._QEMU_MON_HANDLER_CMD = do_clear_log,
  .params       = "big nothing",
  .help	        = "Clears the log"
},