import idc
import idautils

# coutpacket address
COUTPACKET_CONSTRUCT = 0x0068D090
# max number of previouus instructions before skipping
INSTR_DISTANCE_LIMITER = 10
# remove func args from output strings
REMOVE_FUNC_ARGS = True


def demangle_func_name(mangled_name, clean=True):
    demangle_attr = idc.get_inf_attr(INF_SHORT_DN if clean else INF_LONG_DN)
    return idc.demangle_name(mangled_name, demangle_attr)


def is_push_mnem(addr):
    return idc.GetMnem(addr).lower() == "push"


def get_prev_push_addr(base_addr):
    global INSTR_DISTANCE_LIMITER
    prev_op = idautils.DecodePreviousInstruction(base_addr)
    retVal = idaapi.BADADDR  # static value
    
    for idx in range(INSTR_DISTANCE_LIMITER):
        
        # some calls get rekt by asm segments
        if prev_op is None:
            break
            
        if is_push_mnem(prev_op.ea):
            retVal = prev_op.ea
            break
        
        prev_op = idautils.DecodePreviousInstruction(prev_op.ea)
    
    return retVal


# turn decimal opcode into prettyfied hex opcode
def transform_to_hex(raw_addr, padding):
    hex_addr = hex(raw_addr)  # dec -> hex
    l_stripped_addr = hex_addr[2:-1].upper().rjust(padding, '0')  # remove trailing L, capitalize, strip '0x'
    return "0x" + l_stripped_addr  # add lowercase 0x


# get func name from address and demangle it if its mangled
def process_func_name(addr):
    global REMOVE_FUNC_ARGS
    xref_func_name_raw = idc.get_func_name(addr)  # get containing func name
    xref_func_name_clean = demangle_func_name(xref_func_name_raw)  # demangle name
    
    # if name isnt mangled this returns None
    if xref_func_name_clean is None:
        xref_func_name_clean = xref_func_name_raw
    
    if xref_func_name_clean is not None and REMOVE_FUNC_ARGS:
        xref_func_name_clean = xref_func_name_clean.split('(')[0]        
    
    return xref_func_name_clean


# prints all coutpacket constructor call addresses and the opcode argument
def print_opcodes(filter=None):
    global COUTPACKET_CONSTRUCT
    for xref in idautils.XrefsTo(COUTPACKET_CONSTRUCT):  # iterate xrefs
        func_name = process_func_name(xref.frm)
        
        if func_name is None:
            continue
        
        call_addr = get_prev_push_addr(xref.frm)  # get addr to opcode arg
        call_addr_op_val = idc.get_operand_value(call_addr, 0)  # get opcode arg value
        
        if filter is not None:
            # handle single opcode filter
            if type(filter) is int:
                if call_addr_op_val != filter:
                    continue
            # handle list filter
            elif type(filter) is list:
                if call_addr_op_val not in filter:
                    continue
        
        op_val_leg = transform_to_hex(call_addr_op_val, 4)  # prettify opcode
        xref_addr = transform_to_hex(xref.frm, 9)
        
        print("[{}] | [{}] : {}".format(
            xref_addr, 
            op_val_leg, 
            func_name
        ))


# beginning of script execution

print_opcodes()  # no filter
print_opcodes(0x01C4)  # filter by a single opcode
print_opcodes([0x01C4, 0x01C3])  # filter by a list
