# IDAPy-OpCode-Address-Finder-COutPacket-
Find COutPacket in IDA using Python

hi

this is an idapy script that prints COutPacket call addresses and their opcode arguments
can be configured to print everything or filter by one/many opcodes

tested and working on v95, v176, and v213
works with and without a pdb applied
skips calls that have broken asm preceding the call instruction
output is ordered by call address
script requires COutPacket::COutPacket(COutPacket *this, int nType) address entered at the beginning
the function calls on the three last lines of the script are the example usages

enjoy

Spiderman
https://www.youtube.com/channel/UCWXBTq3LuYvs0OEoSr_BZGQ
