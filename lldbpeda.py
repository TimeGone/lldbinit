import binascii
import struct
import re
import lldb

def reverse(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    print("FT_" + str(target)[::-1])

def tohex(val, nbits):
      return hex((val + (1 << nbits)) % (1 << nbits))

def find_value(process, first_value):
    arrow = []
    if "0x00007f" in first_value:
        arrow.append(first_value)
        value = process.GetSelectedThread().GetFrameAtIndex(0).EvaluateExpression('*(long*)' + first_value).unsigned
        arrow.append(str(hex(value)))
        i = 1
        while "0x7fff" in arrow[i]:
            value = process.GetSelectedThread().GetFrameAtIndex(0).EvaluateExpression('*(long*)' + arrow[i]).unsigned
            arrow.append(str(hex(value)))
            i += 1
        if len(arrow) > 1:
            arrow[len(arrow) - 1] = str(hex(process.GetSelectedThread().GetFrameAtIndex(0).EvaluateExpression('*(int*)' + arrow[len(arrow) - 1]).unsigned))

    elif "0x7fff" in first_value:
        arrow.append(first_value)
        value = process.GetSelectedThread().GetFrameAtIndex(0).EvaluateExpression('*(long*)' + first_value).unsigned
        arrow.append(str(hex(value)))
        i = 1
        while "0x7fff" in arrow[i]:
            value = process.GetSelectedThread().GetFrameAtIndex(0).EvaluateExpression('*(long*)' + arrow[i]).unsigned
            arrow.append(str(hex(value)))
            i += 1
        if len(arrow) > 1:
            arrow[len(arrow) - 1] = str(hex(process.GetSelectedThread().GetFrameAtIndex(0).EvaluateExpression('*(long*)' + arrow[len(arrow) - 1]).unsigned))

    return arrow



def continue_with_regs(debugger, command, result, internal_dict):
    debugger.HandleCommand('continue')
    show_regs(debugger, command, result, internal_dict)
    
def next_with_info(debugger, command, result, internal_dict):
    debugger.HandleCommand('thread step-over')
    show_regs(debugger, command, result, internal_dict)


def step_with_info(debugger, command, result, internal_dict):
    debugger.HandleCommand('thread step-in')
    show_regs(debugger, command, result, internal_dict)

def ni_with_info(debugger, command, result, internal_dict):
    debugger.HandleCommand('thread step-inst-over')
    show_regs(debugger, command, result, internal_dict)

def si_with_info(debugger, command, result, internal_dict):
    debugger.HandleCommand('thread step-inst')
    show_regs(debugger, command, result, internal_dict)

def print_reg(process, register, ntimes):
    print("%13.13s" % ('\033[35m' + register.GetName() + "\033[0m ")),  # use format to print r8 and r9 pretty
    print('\033[36m' + register.GetValue() + '\033[0m' + ' '),
    addr = int(register.GetValue(), 16)

    error = lldb.SBError()
    for i in range(ntimes):
        if addr >= 2**64:
            break
        content = process.ReadMemory(addr, 8, error)
        addr = addr + 8
        if error.Success():
            print(binascii.hexlify(content[::-1])),  # use [::-1] to reverse string
    print('')

def show_regs(debugger, command, result, internal_dict):
    print('\033[33m[----------------------------------------------------------------------------registers-------------------------------------------------------------------------]\033[0m')
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    mainThread = process.GetThreadAtIndex(0)
    currentFrame = mainThread.GetSelectedFrame()
    registerList = currentFrame.GetRegisters()
    for value in registerList:
        for child in value:
            if child.GetName() in ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'rbp', 'rsp', 'rip', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'rflags']:
                if child.GetName() == 'rflags':
                    flags = []
                    if int(child.GetValue(), 0) & 0x0001:
                        flags.append("carry")
                    if int(child.GetValue(), 0) & 0x0004:
                        flags.append("parity")
                    if int(child.GetValue(), 0) & 0x0010:
                        flags.append("adjust")
                    if int(child.GetValue(), 0) & 0x0040:
                        flags.append("zero")
                    if int(child.GetValue(), 0) & 0x0080:
                        flags.append("sign")
                    if int(child.GetValue(), 0) & 0x0100:
                        flags.append("trap")
                    if int(child.GetValue(), 0) & 0x0200:
                        flags.append("interrupt")
                    if int(child.GetValue(), 0) & 0x0400:
                        flags.append("direction")
                    if int(child.GetValue(), 0) & 0x0800:
                        flags.append("overflow")

                    flags_peda = ['\033[92m' + x if i % 2 else '\033[91m' + x.upper() for i, x in enumerate(flags)]
                    print('\033[92mrflags \033[0m: ' +child.GetValue().replace("000000000000", "") + ' (' + " | ".join(flags_peda) + '\033[0m)')
                else:
                    # import pdb; pdb.set_trace()
                    print_reg(process, child, 8)

def print_ptr(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    # addr = int(command, 16)
    arg = target.EvaluateExpression(command)
    addr = int(arg.GetValue())
    # import pdb; pdb.set_trace()
    error = lldb.SBError()
    for i in range(8):
        if addr >= 2**64:
            break
        ptr1 = process.ReadPointerFromMemory(addr, error)
        addr = addr + 8
        if not error.Success():
            break
        else:
            hex_ptr = '0x%016x' % ptr1
            print('\033[35m'+ hex_ptr +'\033[0m'),
            for j in range(8):
                if ptr1 >= 2**64:
                    break
                ptr2 = process.ReadPointerFromMemory(ptr1, error)
                if not error.Success():
                    print re.sub('[\x00-\x1f\x7f-\xff]', '.', struct.pack('Q', ptr1))      # replace invisible letters with '.' and print
                    break
                else:
                    ptr1 = ptr1 + 8
                    if j == 0:
                        print('\n-->'),
                    else:
                        print('   '),
                    hex_ptr = '0x%016x' % ptr2
                    print('\033[36m'+ hex_ptr +'\033[0m'),

                    str_buf = ''
                    for k in range(8):
                        if ptr2 >= 2**64:
                            break
                        ptr3 = process.ReadPointerFromMemory(ptr2, error)
                        if not error.Success():
                            print re.sub('[^\x20-\x7e]', '.', struct.pack('Q', ptr2)),
                            break
                        else:
                            ptr2 = ptr2 + 8
                            str_buf = str_buf + struct.pack('Q', ptr3)
                            if k == 0: print('->>'),
                            print('0x%016x' % ptr3),
                    str_re = re.match(r'^[\x20-\x7f]{3,}[\r\n\x00]', str_buf + '\x00')        # start with at lease 3 visible letters, end with \r \n or \x00
                    if str_re != None:
                        print(str_re.group()), 
                    print('')

def code(debugger, command, result, internal_dict):
    print('\033[33m[----------------------------------------Code--------------------------------------]\033[0m')
    cur_pc = debugger.GetSelectedTarget().GetProcess().GetSelectedThread().GetSelectedFrame().GetPC();
    debugger.HandleCommand('disassemble --start-address=' + str(cur_pc) + ' -c 4')
    print('\033[33m[----------------------------------------------------------------------------------]\033[0m')

def stack(debugger, command, result, internal_dict):
    print('\033[33m[---------------------------------------Stack--------------------------------------]\033[0m')
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    cur_sp = process.GetSelectedThread().GetSelectedFrame().GetSP();
    debugger.HandleCommand('x/12gx ' + str(cur_sp))
    print('\033[33m[----------------------------------------------------------------------------------]\033[0m')

def peda(debugger, command, result, internal_dict):
    reg(debugger, command, result, internal_dict)
    code(debugger, command, result, internal_dict)
    stack(debugger, command, result, internal_dict)

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldbpeda.continue_with_regs c')
    debugger.HandleCommand('command script add -f lldbpeda.next_with_info n')
    debugger.HandleCommand('command script add -f lldbpeda.step_with_info s')
    debugger.HandleCommand('command script add -f lldbpeda.ni_with_info ni')
    debugger.HandleCommand('command script add -f lldbpeda.si_with_info si')
    debugger.HandleCommand('command script add -f lldbpeda.show_regs reg')
    debugger.HandleCommand('command script add -f lldbpeda.print_ptr ptr')
    debugger.HandleCommand('command script add -f lldbpeda.code code')
    debugger.HandleCommand('command script add -f lldbpeda.stack stack')
    debugger.HandleCommand('command script add -f lldbpeda.peda peda')
    debugger.HandleCommand('command script add -f lldbpeda.reverse rvs')