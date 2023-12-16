function:
55 53 56 57 41 56 41 57 48 83 EC 68 48 8D 6C 24 20 48 89 8D 80 00 00 00 48 8B D9 
48 83 EC 68 48 8D 6C 24 20 48 89 8D 80 00 00 00 48 8B D9 


path:
C6 45 01 00 48 8D 0D ?? ?? ?? ?? 4C 8D 45 01
48 8D 0D ?? ?? ?? ?? 4C 8D 45 01
4C 8D 45 01

version: 5.520.6157.0
shapr3d.dll + 0x1B39EA4

version: 5.520.6160.0
shapr3d_beta.dll + 0x01B74156


shapr3d-hack_v5-520-6157-0
shapr3d-hack_v5-521-6217-0


Ordinal	Virtual Address	Relative Virtual Address	File Offset Address	Section Name	Characteristics
1	7FFD76B70FCE	01910FCE	0190F5CE	 ".text"		ER---


function:
55 53 56 57 41 56 41 57 48 83 EC 68 48 8D 6C 24 20 48 89 8D 80 00 00 00 48 8B D9 
48 83 EC 68 48 8D 6C 24 20 48 89 8D 80 00 00 00 48 8B D9 




path:
C6 45 01 00 48 8D 0D ?? ?? ?? ?? 4C 8D 45 01
48 8D 0D ?? ?? ?? ?? 4C 8D 45 01
4C 8D 45 01


Shapr3D:
00007FFD76B70E90 | 55                       | push rbp                                |
00007FFD76B70E91 | 53                       | push rbx                                |
00007FFD76B70E92 | 56                       | push rsi                                |
00007FFD76B70E93 | 57                       | push rdi                                |
00007FFD76B70E94 | 41:56                    | push r14                                |

00007FFD76B70E96 | 48:83EC 60               | sub rsp,60                              |
00007FFD76B70E9A | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           |
00007FFD76B70E9F | 48:894D 70               | mov qword ptr ss:[rbp+70],rcx           |
00007FFD76B70EA3 | 48:8BF1                  | mov rsi,rcx                             |
00007FFD76B70EA6 | 33DB                     | xor ebx,ebx                             |

00007FFD76B70EA8 | 48:895D 08               | mov qword ptr ss:[rbp+8],rbx            |
00007FFD76B70EAC | 33C0                     | xor eax,eax                             |
00007FFD76B70EAE | 66:8945 02               | mov word ptr ss:[rbp+2],ax              |
00007FFD76B70EB2 | 48:895D 10               | mov qword ptr ss:[rbp+10],rbx           |
00007FFD76B70EB6 | 48:8945 30               | mov qword ptr ss:[rbp+30],rax           |
00007FFD76B70EBA | 8B01                     | mov eax,dword ptr ds:[rcx]              |
00007FFD76B70EBC | 48:8B49 18               | mov rcx,qword ptr ds:[rcx+18]           |
00007FFD76B70EC0 | 48:894D 18               | mov qword ptr ss:[rbp+18],rcx           |
00007FFD76B70EC4 | 885D 00                  | mov byte ptr ss:[rbp],bl                |
00007FFD76B70EC7 | 48:895D 28               | mov qword ptr ss:[rbp+28],rbx           |
00007FFD76B70ECB | 90                       | nop                                     |


Shapr3D_Beta:
00007FFD76A12FC0 | 55                       | push rbp                                |
00007FFD76A12FC1 | 53                       | push rbx                                |
00007FFD76A12FC2 | 56                       | push rsi                                |
00007FFD76A12FC3 | 57                       | push rdi                                |
00007FFD76A12FC4 | 41:56                    | push r14                                | r14:"MZђ"
00007FFD76A12FC6 | 41:57                    | push r15                                |

00007FFD76A12FC8 | 48:83EC 68               | sub rsp,68                              |
00007FFD76A12FCC | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           | [ss:[rsp+20]]:SRCacheManager_SetProperty_UInt32+56F
00007FFD76A12FD1 | 48:898D 80000000         | mov qword ptr ss:[rbp+80],rcx           |
00007FFD76A12FD8 | 48:8BD9                  | mov rbx,rcx                             | rcx:"MZђ"
00007FFD76A12FDB | 33F6                     | xor esi,esi                             |

00007FFD76A12FDD | 48:8975 10               | mov qword ptr ss:[rbp+10],rsi           |
00007FFD76A12FE1 | 48:8975 08               | mov qword ptr ss:[rbp+8],rsi            |
00007FFD76A12FE5 | 48:8975 20               | mov qword ptr ss:[rbp+20],rsi           |
00007FFD76A12FE9 | 33C0                     | xor eax,eax                             |
00007FFD76A12FEB | 66:8945 02               | mov word ptr ss:[rbp+2],ax              |
00007FFD76A12FEF | 48:8945 38               | mov qword ptr ss:[rbp+38],rax           | rax:DllGetActivationFactory+2CA0
00007FFD76A12FF3 | 8B39                     | mov edi,dword ptr ds:[rcx]              | dword ptr ds:[rcx]:"MZђ"
00007FFD76A12FF5 | 4C:8B79 20               | mov r15,qword ptr ds:[rcx+20]           |
00007FFD76A12FF9 | 8845 00                  | mov byte ptr ss:[rbp],al                |
00007FFD76A12FFC | 48:8975 30               | mov qword ptr ss:[rbp+30],rsi           |
00007FFD76A13000 | 90                       | nop                                     |




5.521.6217.0
00007FFFE159E0C0 | 55                       | push rbp                                |
00007FFFE159E0C1 | 53                       | push rbx                                |
00007FFFE159E0C2 | 56                       | push rsi                                |
00007FFFE159E0C3 | 57                       | push rdi                                |
00007FFFE159E0C4 | 41:56                    | push r14                                | r14:"MZђ"
00007FFFE159E0C6 | 41:57                    | push r15                                |
00007FFFE159E0C8 | 48:83EC 68               | sub rsp,68                              |
00007FFFE159E0CC | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           |
00007FFFE159E0D1 | 48:898D 80000000         | mov qword ptr ss:[rbp+80],rcx           |
00007FFFE159E0D8 | 48:8BD9                  | mov rbx,rcx                             | rcx:"MZђ"
00007FFFE159E0DB | 33F6                     | xor esi,esi                             |
00007FFFE159E0DD | 48:8975 08               | mov qword ptr ss:[rbp+8],rsi            |
00007FFFE159E0E1 | 48:8975 20               | mov qword ptr ss:[rbp+20],rsi           |
00007FFFE159E0E5 | 48:8975 38               | mov qword ptr ss:[rbp+38],rsi           |
00007FFFE159E0E9 | 44:8B31                  | mov r14d,dword ptr ds:[rcx]             | rcx:"MZђ"
00007FFFE159E0EC | 48:8B79 18               | mov rdi,qword ptr ds:[rcx+18]           |
00007FFFE159E0F0 | 48:897D 28               | mov qword ptr ss:[rbp+28],rdi           |
00007FFFE159E0F4 | 8975 00                  | mov dword ptr ss:[rbp],esi              |
00007FFFE159E0F7 | 48:8975 30               | mov qword ptr ss:[rbp+30],rsi           |
00007FFFE159E0FB | 90                       | nop                                     |
00007FFFE159E0FC | 8BC6                     | mov eax,esi                             |
00007FFFE159E0FE | 45:85F6                  | test r14d,r14d                          |
00007FFFE159E101 | 74 13                    | je shapr3d.7FFFE159E116                 |
00007FFFE159E103 | 48:8B4F 18               | mov rcx,qword ptr ds:[rdi+18]           | rcx:"MZђ"
00007FFFE159E107 | E8 54ADFFFF              | call shapr3d.7FFFE1598E60               |
00007FFFE159E10C | 48:85C0                  | test rax,rax                            |
00007FFFE159E10F | 75 05                    | jne shapr3d.7FFFE159E116                |
00007FFFE159E111 | E9 9E010000              | jmp shapr3d.7FFFE159E2B4                |
00007FFFE159E116 | 48:8975 10               | mov qword ptr ss:[rbp+10],rsi           |
00007FFFE159E11A | 45:85F6                  | test r14d,r14d                          |
00007FFFE159E11D | 74 61                    | je shapr3d.7FFFE159E180                 |
00007FFFE159E11F | 48:8B4B 20               | mov rcx,qword ptr ds:[rbx+20]           | rcx:"MZђ"
00007FFFE159E123 | 8039 00                  | cmp byte ptr ds:[rcx],0                 | rcx:"MZђ"
00007FFFE159E126 | 4C:8BC8                  | mov r9,rax                              |
00007FFFE159E129 | 4C:8B47 10               | mov r8,qword ptr ds:[rdi+10]            |
00007FFFE159E12D | 48:8B57 08               | mov rdx,qword ptr ds:[rdi+8]            |
00007FFFE159E131 | E8 4A030000              | call shapr3d.7FFFE159E480               |
00007FFFE159E136 | 8038 00                  | cmp byte ptr ds:[rax],0                 |
00007FFFE159E139 | 48:8975 38               | mov qword ptr ss:[rbp+38],rsi           |
00007FFFE159E13D | 48:8945 08               | mov qword ptr ss:[rbp+8],rax            |
00007FFFE159E141 | 48:8BC8                  | mov rcx,rax                             | rcx:"MZђ"
00007FFFE159E144 | FF15 B66628FF            | call qword ptr ds:[7FFFE0824800]        |
00007FFFE159E14A | 84C0                     | test al,al                              |
00007FFFE159E14C | 75 2C                    | jne shapr3d.7FFFE159E17A                |
00007FFFE159E14E | 8933                     | mov dword ptr ds:[rbx],esi              |
00007FFFE159E150 | 48:8D4B 30               | lea rcx,qword ptr ds:[rbx+30]           | rcx:"MZђ"
00007FFFE159E154 | 48:8B55 08               | mov rdx,qword ptr ss:[rbp+8]            |
00007FFFE159E158 | FF15 A2CD28FF            | call qword ptr ds:[<&RhpCheckedAssignRe |
00007FFFE159E15E | 48:8D15 A3AFA0FE         | lea rdx,qword ptr ds:[7FFFDFFA9108]     | 00007FFFDFFA9108:&"°ЖРЯя\x7F"
00007FFFE159E165 | 48:8D4B 08               | lea rcx,qword ptr ds:[rbx+8]            | rcx:"MZђ"
00007FFFE159E169 | 4C:8BCB                  | mov r9,rbx                              |
00007FFFE159E16C | 4C:8D45 08               | lea r8,qword ptr ss:[rbp+8]             |
00007FFFE159E170 | E8 5BBB98FF              | call shapr3d.7FFFE0F29CD0               |
00007FFFE159E175 | E9 53010000              | jmp shapr3d.7FFFE159E2CD                |
00007FFFE159E17A | 48:8B4D 08               | mov rcx,qword ptr ss:[rbp+8]            |
00007FFFE159E17E | EB 12                    | jmp shapr3d.7FFFE159E192                |
00007FFFE159E180 | 48:8B4B 30               | mov rcx,qword ptr ds:[rbx+30]           | rcx:"MZђ"
00007FFFE159E184 | 48:894D 08               | mov qword ptr ss:[rbp+8],rcx            |
00007FFFE159E188 | 48:8973 30               | mov qword ptr ds:[rbx+30],rsi           |
00007FFFE159E18C | C703 FFFFFFFF            | mov dword ptr ds:[rbx],FFFFFFFF         |
00007FFFE159E192 | FF15 206E28FF            | call qword ptr ds:[7FFFE0824FB8]        |
00007FFFE159E198 | 48:8B45 08               | mov rax,qword ptr ss:[rbp+8]            |
00007FFFE159E19C | 48:8B48 48               | mov rcx,qword ptr ds:[rax+48]           | rcx:"MZђ"
00007FFFE159E1A0 | 48:894D 10               | mov qword ptr ss:[rbp+10],rcx           |
00007FFFE159E1A4 | 48:8B5D 10               | mov rbx,qword ptr ss:[rbp+10]           |
00007FFFE159E1A8 | 48:85DB                  | test rbx,rbx                            |
00007FFFE159E1AB | 75 0A                    | jne shapr3d.7FFFE159E1B7                |
00007FFFE159E1AD | 33F6                     | xor esi,esi                             |
00007FFFE159E1AF | 8975 00                  | mov dword ptr ss:[rbp],esi              |
00007FFFE159E1B2 | E9 FD000000              | jmp shapr3d.7FFFE159E2B4                |
00007FFFE159E1B7 | E8 44ACFFFF              | call shapr3d.7FFFE1598E00               |
00007FFFE159E1BC | 4C:8B7B 08               | mov r15,qword ptr ds:[rbx+8]            |
00007FFFE159E1C0 | 48:8B4B 20               | mov rcx,qword ptr ds:[rbx+20]           | rcx:"MZђ"
00007FFFE159E1C4 | FF15 063F28FF            | call qword ptr ds:[7FFFE08220D0]        |
00007FFFE159E1CA | 33F6                     | xor esi,esi                             |
00007FFFE159E1CC | 84C0                     | test al,al                              |
00007FFFE159E1CE | 75 06                    | jne shapr3d.7FFFE159E1D6                |
00007FFFE159E1D0 | 4C:8B73 20               | mov r14,qword ptr ds:[rbx+20]           | r14:"MZђ"
00007FFFE159E1D4 | EB 03                    | jmp shapr3d.7FFFE159E1D9                |
00007FFFE159E1D6 | 4C:8BF6                  | mov r14,rsi                             | r14:"MZђ"
00007FFFE159E1D9 | 48:8B85 80000000         | mov rax,qword ptr ss:[rbp+80]           |
00007FFFE159E1E0 | 48:8B78 28               | mov rdi,qword ptr ds:[rax+28]           |
00007FFFE159E1E4 | 48:8D0D FD115BFE         | lea rcx,qword ptr ds:[7FFFDFB4F3E8]     | rcx:"MZђ"
00007FFFE159E1EB | FF15 E7CC28FF            | call qword ptr ds:[<&RhpNewFast>]       |
00007FFFE159E1F1 | 48:8BD8                  | mov rbx,rax                             |
00007FFFE159E1F4 | 4D:8BC6                  | mov r8,r14                              | r14:"MZђ"
00007FFFE159E1F7 | 49:8BD7                  | mov rdx,r15                             |
00007FFFE159E1FA | 48:8BC8                  | mov rcx,rax                             | rcx:"MZђ"
00007FFFE159E1FD | E8 0E00D9FF              | call shapr3d.7FFFE132E210               |
00007FFFE159E202 | 803F 00                  | cmp byte ptr ds:[rdi],0                 |
00007FFFE159E205 | 48:8BCF                  | mov rcx,rdi                             | rcx:"MZђ"
00007FFFE159E208 | 48:8BD3                  | mov rdx,rbx                             |
00007FFFE159E20B | E8 70010000              | call shapr3d.7FFFE159E380               |
00007FFFE159E210 | 48:8B45 28               | mov rax,qword ptr ss:[rbp+28]           |
00007FFFE159E214 | 8B48 20                  | mov ecx,dword ptr ds:[rax+20]           |
00007FFFE159E217 | 85C9                     | test ecx,ecx                            |
00007FFFE159E219 | 74 4D                    | je shapr3d.7FFFE159E268                 |
00007FFFE159E21B | 83F9 01                  | cmp ecx,1                               |
00007FFFE159E21E | 74 22                    | je shapr3d.7FFFE159E242                 |
00007FFFE159E220 | 48:8B0D F99F28FF         | mov rcx,qword ptr ds:[7FFFE0828220]     | rcx:"MZђ", 00007FFFE0828220:"иEЂея\x7F"
00007FFFE159E227 | FF15 ABCC28FF            | call qword ptr ds:[<&RhpNewFast>]       |
00007FFFE159E22D | 48:8BD8                  | mov rbx,rax                             |
00007FFFE159E230 | 48:8BC8                  | mov rcx,rax                             | rcx:"MZђ"
00007FFFE159E233 | FF15 9F3328FF            | call qword ptr ds:[7FFFE08215D8]        |
00007FFFE159E239 | 48:8BCB                  | mov rcx,rbx                             | rcx:"MZђ"
00007FFFE159E23C | FF15 0ECD28FF            | call qword ptr ds:[<&RhpThrowEx>]       |
00007FFFE159E242 | 48:8975 18               | mov qword ptr ss:[rbp+18],rsi           |
00007FFFE159E246 | C645 18 01               | mov byte ptr ss:[rbp+18],1              |
00007FFFE159E24A | 48:8D0D F76D5AFE         | lea rcx,qword ptr ds:[7FFFDFB45048]     | rcx:"MZђ"
00007FFFE159E251 | FF15 81CC28FF            | call qword ptr ds:[<&RhpNewFast>]       |
00007FFFE159E257 | 48:8BD8                  | mov rbx,rax                             |
00007FFFE159E25A | 48:8B55 18               | mov rdx,qword ptr ss:[rbp+18]           |
00007FFFE159E25E | 48:8BC8                  | mov rcx,rax                             | rcx:"MZђ"
00007FFFE159E261 | E8 2A43F4FF              | call shapr3d.7FFFE14E2590               |
00007FFFE159E266 | EB 18                    | jmp shapr3d.7FFFE159E280                |
00007FFFE159E268 | 48:8D0D E96C5AFE         | lea rcx,qword ptr ds:[7FFFDFB44F58]     | rcx:"MZђ"
00007FFFE159E26F | FF15 63CC28FF            | call qword ptr ds:[<&RhpNewFast>]       |
00007FFFE159E275 | 48:8BD8                  | mov rbx,rax                             |
00007FFFE159E278 | 48:8BC8                  | mov rcx,rax                             | rcx:"MZђ"
00007FFFE159E27B | E8 D0000000              | call shapr3d.7FFFE159E350               |
00007FFFE159E280 | 48:8BCB                  | mov rcx,rbx                             | rcx:"MZђ"
00007FFFE159E283 | E8 D87A75FF              | call shapr3d.7FFFE0CF5D60               |
00007FFFE159E288 | 48:8D15 719C2AFF         | lea rdx,qword ptr ds:[7FFFE0847F00]     |
00007FFFE159E28F | FF15 53CC28FF            | call qword ptr ds:[<&RhpCheckCctor2>]   |
00007FFFE159E295 | 48:8D05 ACF128FF         | lea rax,qword ptr ds:[7FFFE082D448]     | 00007FFFE082D448:"h®Н‘)\x02"
00007FFFE159E29C | 48:8B48 10               | mov rcx,qword ptr ds:[rax+10]           | rcx:"MZђ"
00007FFFE159E2A0 | 8039 00                  | cmp byte ptr ds:[rcx],0                 | rcx:"MZђ"
00007FFFE159E2A3 | 4C:8D15 66A248FF         | lea r10,qword ptr ds:[<&JMP.&RhpInitial | 00007FFFE0A28510:"H\fЉбя\x7F"
00007FFFE159E2AA | 41:FF12                  | call qword ptr ds:[r10]                 |
00007FFFE159E2AD | C745 00 02000000         | mov dword ptr ss:[rbp],2                |
00007FFFE159E2B4 | 48:8B8D 80000000         | mov rcx,qword ptr ss:[rbp+80]           |
00007FFFE159E2BB | C701 FEFFFFFF            | mov dword ptr ds:[rcx],FFFFFFFE         | rcx:"MZђ"
00007FFFE159E2C1 | 48:83C1 08               | add rcx,8                               | rcx:"MZђ"
00007FFFE159E2C5 | 8B55 00                  | mov edx,dword ptr ss:[rbp]              |
00007FFFE159E2C8 | E8 83B798FF              | call shapr3d.7FFFE0F29A50               |
00007FFFE159E2CD | 90                       | nop                                     |
00007FFFE159E2CE | 48:8D65 48               | lea rsp,qword ptr ss:[rbp+48]           |
00007FFFE159E2D2 | 41:5F                    | pop r15                                 |
00007FFFE159E2D4 | 41:5E                    | pop r14                                 | r14:"MZђ"
00007FFFE159E2D6 | 5F                       | pop rdi                                 |
00007FFFE159E2D7 | 5E                       | pop rsi                                 |
00007FFFE159E2D8 | 5B                       | pop rbx                                 |
00007FFFE159E2D9 | 5D                       | pop rbp                                 |
00007FFFE159E2DA | C3                       | ret                                     |





55 53 56 57 41 54 41 56 41 57 48 83 EC 60 48 8D 6C 24 20 48 89 8D 80 00 00 00 48 8B D9 
00007FFFE15A0E20 | 55                       | push rbp                                |
00007FFFE15A0E21 | 53                       | push rbx                                |
00007FFFE15A0E22 | 56                       | push rsi                                |
00007FFFE15A0E23 | 57                       | push rdi                                |
00007FFFE15A0E24 | 41:54                    | push r12                                |
00007FFFE15A0E26 | 41:56                    | push r14                                |
00007FFFE15A0E28 | 41:57                    | push r15                                | r15:&"(o,·)\x02"
00007FFFE15A0E2A | 48:83EC 60               | sub rsp,60                              |
00007FFFE15A0E2E | 48:8D6C24 20             | lea rbp,qword ptr ss:[rsp+20]           |
00007FFFE15A0E33 | 48:898D 80000000         | mov qword ptr ss:[rbp+80],rcx           |
00007FFFE15A0E3A | 48:8BD9                  | mov rbx,rcx                             |

88 45 00 48 89 7D 28 90 
00007FFFE15A0E57 | 8845 00                  | mov byte ptr ss:[rbp],al                |
00007FFFE15A0E5A | 48:897D 28               | mov qword ptr ss:[rbp+28],rdi           |
00007FFFE15A0E5E | 90                       | nop                                     |

founding;
90 85 F6 74 36 
00007FFFE15A0E5E | 90                       | nop                                     |
00007FFFE15A0E5F | 85F6                     | test esi,esi                            |
00007FFFE15A0E61 | 74 36                    | je shapr3d.7FFFE15A0E99                 |

founding;
88 45 00 48 89 ?? ?? 90 85 F6
00007FFD44AA9109 | 8845 00                  | mov byte ptr ss:[rbp],al                |
00007FFD44AA910C | 48:895D 30               | mov qword ptr ss:[rbp+30],rbx           |
00007FFD44AA9110 | 90                       | nop                                     |
00007FFD44AA9111 | 85F6                     | test esi,esi                            |

48 8B 53 ?? 48 8B C1 
00007FFFE15A0F3F | 48:8B53 18               | mov rdx,qword ptr ds:[rbx+18]           |
00007FFFE15A0F43 | 48:8BC1                  | mov rax,rcx                             | rcx:"MZђ"

4C 8D 45 03 48 8B
00007FFD44AA91EE | 4C:8D45 03               | lea r8,qword ptr ss:[rbp+3]             |

4C 8D 45 03 48 8B 53 ?? E8 ?? ?? ?? ?? 
00007FFFE15A0F3B | 4C:8D45 03               | lea r8,qword ptr ss:[rbp+3]             |
00007FFFE15A0F3F | 48:8B53 18               | mov rdx,qword ptr ds:[rbx+18]           |
00007FFFE15A0F43 | E8 88F578FF              | call shapr3d.7FFFE0D304D0               |


00007FFFE15A0F2B | E9 F4000000              | jmp shapr3d.7FFFE15A1024                |
00007FFFE15A0F30 | C645 03 00               | mov byte ptr ss:[rbp+3],0               |
00007FFFE15A0F34 | 48:8D0D 7D92A2FE         | lea rcx,qword ptr ds:[7FFFDFFCA1B8]     | rcx:"MZђ", 00007FFFDFFCA1B8:"Р`ЪЯя\x7F"
00007FFFE15A0F3B | 4C:8D45 03               | lea r8,qword ptr ss:[rbp+3]             |
00007FFFE15A0F3F | 48:8B53 18               | mov rdx,qword ptr ds:[rbx+18]           |
00007FFFE15A0F43 | E8 88F578FF              | call shapr3d.7FFFE0D304D0               | <---
00007FFFE15A0F48 | 4C:8BF8                  | mov r15,rax                             |
00007FFFE15A0F4B | 4C:8B63 08               | mov r12,qword ptr ds:[rbx+8]            |
00007FFFE15A0F4F | 48:8B4B 10               | mov rcx,qword ptr ds:[rbx+10]           | rcx:"MZђ"
00007FFFE15A0F53 | FF15 771128FF            | call qword ptr ds:[7FFFE08220D0]        |
00007FFFE15A0F59 | 84C0                     | test al,al                              |

00007FFFE15A0F43
1B40F43
1B3D743

hack:
48 8B C1 90 90



Shapr3D.Shapr3DBeta_5.521.6218.0_x64__dvv5p1vgwv6mp
00007FFD44AA91F6
1B791F6
