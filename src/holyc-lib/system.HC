#include "./defs.HH"

extern "c" U0 exit(I32 code);
extern "c" I64 system(U8 *command);
extern "c" I64 write(I32 fd, U0 *buf, U64 count);

#ifdef IS_X86_64
#define SYS_CALL_WRITE 0x2000004 /* Non portable */

asm {
_EXIT::
    CALL    exit

_SYSTEM::
    PUSHQ  RBP
    MOVQ   RBP, RSP
    CALL   system
    LEAVE
    RET

_WRITE::
    MOVQ    RAX, SYS_CALL_WRITE
    SYSCALL
    LEAVE
    RET
}

public _extern _EXIT U0 Exit(I64 exit_code=EXIT_FAIL);
public _extern _WRITE I64 Write(I64 fd, U8 *buf, I64 len);
public _extern _SYSTEM I64 System(U8 *command);

#else

public U0 Exit(I64 exit_code=EXIT_FAIL) {
  exit(exit_code(I32));
}

public I64 Write(I64 fd, U8 *buf, I64 len) {
  return write(fd(I32), buf, len);
}

public I64 System(U8 *command) {
  return system(command);
}

#endif
