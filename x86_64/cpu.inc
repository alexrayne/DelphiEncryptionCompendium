{*****************************************************************************

  Delphi Encryption Compendium (DEC Part I)
  Version 5.3 for Delphi 7 - 10.4 or higher/FPC 2.6 or higher

  Remarks:          Freeware, Copyright must be included

  Original Author:  (c) 2006 Hagen Reddmann, HaReddmann [at] T-Online [dot] de
  Modifications:    (c) 2008 Arvid Winkelsdorf, info [at] digivendo [dot] de
                    (c) 2017, 2021 decfpc
                    (c) 2022 alexrain

 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*****************************************************************************}

{$ASMMODE intel}


{check is CPUID Instruction present}
function CPUID_Found: LongBool; assembler;
asm
  pushfq
  pushfq
  pop    rax
  mov    rdx, rax
  xor    rax, 0040000h
  push   rax
  popfq
  pushfq
  pop    rax
  xor    rax, rdx
  jz     @@1
  pushfq
  pop    rax
  mov    rdx, rax
  xor    rax, 0200000h
  push   rax
  popfq
  pushfq
  pop    rax
  xor    rax, rdx
@@1:
  popfq
end;

procedure DoCPUID64;
asm
       PUSH    RDI
       PUSH    RBX

       MOV     RDI,OFFSET FCPU
       LEA     RDI,[RDI].TCPUData.Vendor
       XOR     RAX,RAX
       CPUID
       MOV     [RDI + 0],EBX
       MOV     [RDI + 4],EDX
       MOV     [RDI + 8],ECX

       MOV     RDI,OFFSET FCPU
       CMP     EAX,2
       JL      @@1
       MOV     EAX,2
       CPUID
       MOV     [RDI].TCPUData.TLB_EAX,EAX
       MOV     [RDI].TCPUData.TLB_EDX,EDX
       MOV     [RDI].TCPUData.TLB_EBX,EBX
       MOV     [RDI].TCPUData.TLB_ECX,ECX
@@1:   MOV     EAX,1
       XOR     EBX,EBX
       XOR     ECX,ECX
       CPUID
       MOV     [RDI].TCPUData.Signature,EAX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[0],EAX
       MOV     [RDI].TCPUData.Features_EDX,EDX
       MOV     [RDI].TCPUData.Features_EBX,EBX
       MOV     [RDI].TCPUData.Features_ECX,ECX

       MOV     EDX,EAX
       AND     EAX,0Fh
       MOV     [RDI].TCPUData.Stepping,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [RDI].TCPUData.Model,AL
       SHR     EDX,4
       MOV     EAX,EDX
       AND     EAX,0Fh
       MOV     [RDI].TCPUData.Family,AL
       SHR     EDX,4
       AND     EDX,0Fh
       MOV     [RDI].TCPUData.Typ,DL

       MOV     EAX,080000000h
       XOR     EDX,EDX
       XOR     EAX,EAX
       CPUID
       TEST    EAX,EAX
       JLE     @@3
       AND     EDX,EDX
       JZ      @@3
       PUSH    RAX
       MOV     EAX,080000001h
       CPUID
       MOV     [RDI].TCPUData.FeaturesEx_EDX,EDX
       MOV     [RDI].TCPUData.FeaturesEx_EBX,EBX
       MOV     [RDI].TCPUData.FeaturesEx_ECX,ECX
       POP     RAX
       CMP     EAX,1
       JBE     @@3
       PUSH    RSI
       PUSH    RDI
       XOR     ESI,ESI
       LEA     RDI,[RDI].TCPUData.VendorEx
@@2:   LEA     EAX,[080000002h + ESI]
       XOR     EDX,EDX
       XOR     EBX,EBX
       XOR     ECX,ECX
       CPUID
       MOV     [RDI +  0],EAX
       MOV     [RDI +  4],EBX
       MOV     [RDI +  8],ECX
       MOV     [RDI + 12],EDX
       INC     ESI
       ADD     RDI,16
       AND     ESI,3
       JNZ     @@2
       POP     RDI
       POP     RSI

@@3:   XOR     EDX,EDX
       XOR     ECX,ECX
       XOR     EBX,EBX
       MOV     EAX,3
       CPUID
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[ 4],EDX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[ 8],ECX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[12],EBX
       MOV     DWord Ptr [RDI].TCPUData.CPUID3[16],EAX
       POP     RBX
       POP     RDI
end;


{initialize the CPU Datastruct}
procedure GetCPU;

  function CRC(const Value): Cardinal; assembler;
  asm
      mov  eax, [rcx+0]
      xor  eax, [rcx+4]
      xor  eax, [rcx+8]
  end;

begin
  FillChar(FCPU, SizeOf(FCPU), 0);
  if CPUID_Found then
     DoCPUID64;
  FCPU.VendorID := CRC(FCPU.Vendor);
end;

