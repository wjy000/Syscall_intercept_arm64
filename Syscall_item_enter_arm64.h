
//获取系统调用名称
const char *getSyscallName(long rax);

void SysCall_item_enter_switch(pid_t pid, user_pt_regs regs);