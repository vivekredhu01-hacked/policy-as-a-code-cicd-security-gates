# F04 clean container control

This control uses a scratch image with no operating-system packages and
contains no intentional container vulnerability. It is intentionally minimal:
the scan target is the image filesystem, not a runnable application.
